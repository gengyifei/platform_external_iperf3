/*
 * iperf, Copyright (c) 2014-2021, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <sys/time.h>
#include <sys/select.h>

#include "iperf.h"
#include "iperf_api.h"
#include "iperf_util.h"
#include "iperf_dccp.h"
#include "timer.h"
#include "net.h"
#include "cjson.h"
#include "portable_endian.h"

int
iperf_dccp_recv(struct iperf_stream *sp)
{
#if defined(HAVE_DCCP_H)
    uint32_t  sec, usec, pc;
    uint64_t  pcount;
    int       r;
    int       size = sp->settings->blksize;
    int       first_packet = 0;
    double    transit = 0, d = 0;
    struct iperf_time sent_time, arrival_time, temp_time;

    r = Nread(sp->socket, sp->buffer, size, Pdccp);

    /*
     * If we got an error in the read, or if we didn't read anything
     * because the underlying read(2) got a EAGAIN, then skip packet
     * processing.
     */
    if (r <= 0)
        return r;

    /* Only count bytes received while we're in the correct state. */
    if (sp->test->state == TEST_RUNNING) {

    /*
     * For jitter computation below, it's important to know if this
     * packet is the first packet received.
     */
    if (sp->result->bytes_received == 0) {
        first_packet = 1;
    }

    sp->result->bytes_received += r;
    sp->result->bytes_received_this_interval += r;

    memcpy(&sec, sp->buffer, sizeof(sec));
    memcpy(&usec, sp->buffer+4, sizeof(usec));
    memcpy(&pc, sp->buffer+8, sizeof(pc));
    sec = ntohl(sec);
    usec = ntohl(usec);
    pcount = ntohl(pc);
    sent_time.secs = sec;
    sent_time.usecs = usec;


    if (sp->test->debug)
        fprintf(stderr, "pcount %" PRIu64 " packet_count %d\n", pcount, sp->packet_count);

    /*
     * Try to handle out of order packets.  The way we do this
     * uses a constant amount of storage but might not be
     * correct in all cases.  In particular we seem to have the
     * assumption that packets can't be duplicated in the network,
     * because duplicate packets will possibly cause some problems here.
     *
     * First figure out if the sequence numbers are going forward.
     * Note that pcount is the sequence number read from the packet,
     * and sp->packet_count is the highest sequence number seen so
     * far (so we're expecting to see the packet with sequence number
     * sp->packet_count + 1 arrive next).
     */
    if (pcount >= sp->packet_count + 1) {
        /* Forward, but is there a gap in sequence numbers? */
        if (pcount > sp->packet_count + 1) {
            /* There's a gap so count that as a loss. */
            sp->cnt_error += (pcount - 1) - sp->packet_count;
        }
        /* Update the highest sequence number seen so far. */
        sp->packet_count = pcount;
    } else {
        /*
         * Sequence number went backward (or was stationary?!?).
         * This counts as an out-of-order packet.
         */
        sp->outoforder_packets++;

        /*
         * If we have lost packets, then the fact that we are now
         * seeing an out-of-order packet offsets a prior sequence
         * number gap that was counted as a loss.  So we can take
         * away a loss.
         */
        if (sp->cnt_error > 0)
            sp->cnt_error--;

        /* Log the out-of-order packet */
        if (sp->test->debug)
            fprintf(stderr, "OUT OF ORDER - incoming packet sequence %" PRIu64 " but expected sequence %d on stream %d", pcount, sp->packet_count + 1, sp->socket);
    }

    /*
     * jitter measurement
     *
     * This computation is based on RFC 1889 (specifically
     * sections 6.3.1 and A.8).
     *
     * Note that synchronized clocks are not required since
     * the source packet delta times are known.  Also this
     * computation does not require knowing the round-trip
     * time.
     */
    iperf_time_now(&arrival_time);

    iperf_time_diff(&arrival_time, &sent_time, &temp_time);
    transit = iperf_time_in_secs(&temp_time);

    /* Hack to handle the first packet by initializing prev_transit. */
    if (first_packet)
        sp->prev_transit = transit;

    d = transit - sp->prev_transit;
    if (d < 0)
        d = -d;
    sp->prev_transit = transit;
    sp->jitter += (d - sp->jitter) / 16.0;
    }
    else {
        if (sp->test->debug)
            printf("Late receive, state = %d\n", sp->test->state);
    }

    return r;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}


int
iperf_dccp_send(struct iperf_stream *sp)
{
#if defined(HAVE_DCCP_H)
    uint32_t  sec, usec, pcount;
    int r;
    int       size = sp->settings->blksize;
    struct iperf_time before;

    iperf_time_now(&before);

    ++sp->packet_count;

    sec = htonl(before.secs);
    usec = htonl(before.usecs);
    pcount = htonl(sp->packet_count);

    memcpy(sp->buffer, &sec, sizeof(sec));
    memcpy(sp->buffer+4, &usec, sizeof(usec));
    memcpy(sp->buffer+8, &pcount, sizeof(pcount));

    r = Nwrite(sp->socket, sp->buffer, size, Pdccp);

    if (r < 0)
        return r;

    sp->result->bytes_sent += r;
    sp->result->bytes_sent_this_interval += r;

    if (sp->test->debug)
        printf("sent %d bytes of %d, total %" PRIu64 "\n", r, sp->settings->blksize, sp->result->bytes_sent);

    return r;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}

int
iperf_dccp_accept(struct iperf_test * test)
{
#if defined(HAVE_DCCP_H)
    int     s;
    signed char rbuf = ACCESS_DENIED;
    char    cookie[COOKIE_SIZE];
    socklen_t len;
    struct sockaddr_storage addr;

    len = sizeof(addr);
    s = accept(test->listener, (struct sockaddr *) &addr, &len);
    if (s < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if (Nread(s, cookie, COOKIE_SIZE, Pdccp) < 0) {
        i_errno = IERECVCOOKIE;
        close(s);
        return -1;
    }

    if (strncmp(test->cookie, cookie, COOKIE_SIZE) != 0) {
        if (Nwrite(s, (char*) &rbuf, sizeof(rbuf), Pdccp) < 0) {
            i_errno = IESENDMESSAGE;
            close(s);
            return -1;
        }
        close(s);
    }

    return s;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}

int
iperf_dccp_listen(struct iperf_test *test)
{
#if defined(HAVE_DCCP_H)
    struct addrinfo hints, *res;
    char portstr[6];
    int s, opt, saved_errno;

    close(test->listener);

    snprintf(portstr, 6, "%d", test->server_port);
    memset(&hints, 0, sizeof(hints));
    /*
     * If binding to the wildcard address with no explicit address
     * family specified, then force us to get an AF_INET6 socket.
     * More details in the comments in netanounce().
     */
    if (test->settings->domain == AF_UNSPEC && !test->bind_address) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = test->settings->domain;
    }
    hints.ai_socktype = 0;
    hints.ai_flags = AI_PASSIVE;
    if ((gerror = getaddrinfo(test->bind_address, portstr, &hints, &res)) != 0) {
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    if ((s = socket(res->ai_family, SOCK_DCCP, IPPROTO_DCCP)) < 0) {
        freeaddrinfo(res);
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    if ((opt = test->settings->socket_bufsize)) {
        int saved_errno;
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }

    if (test->bind_dev) {
#if defined(SO_BINDTODEVICE)
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
                       test->bind_dev, IFNAMSIZ) < 0)
#endif // SO_BINDTODEVICE
        {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            i_errno = IEBINDDEV;
            errno = saved_errno;
            return -1;
        }
    }

#if defined(IPV6_V6ONLY) && !defined(__OpenBSD__)
    if (res->ai_family == AF_INET6 && (test->settings->domain == AF_UNSPEC ||
        test->settings->domain == AF_INET6)) {
        if (test->settings->domain == AF_UNSPEC)
            opt = 0;
        else
            opt = 1;
        if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
                (char *) &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IEPROTOCOL;
            return -1;
        }
    }
#endif /* IPV6_V6ONLY */

    opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(res);
        errno = saved_errno;
        i_errno = IEREUSEADDR;
        return -1;
    }

    if ((opt = test->settings->multipath)) {
        int saved_errno;
        if (setsockopt(s, SOL_DCCP, DCCP_SOCKOPT_MULTIPATH, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(res);
            errno = saved_errno;
            i_errno = IEMULTIPATH;
            return -1;
        }
    }

    if (bind(s, (struct sockaddr *) res->ai_addr, res->ai_addrlen) < 0) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(res);
        errno = saved_errno;
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    freeaddrinfo(res);

    if (listen(s, INT_MAX) < 0) {
        i_errno = IESTREAMLISTEN;
        return -1;
    }

    test->listener = s;

    return s;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}

int
iperf_dccp_connect(struct iperf_test *test)
{
#if defined(HAVE_DCCP_H)
    int s, opt, saved_errno;
    struct addrinfo *server_res = NULL;

    s = create_socket(test->settings->domain, SOCK_DCCP, test->bind_address, test->bind_dev, test->bind_port, test->server_hostname, test->server_port, &server_res);
    if (s < 0) {
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    if ((opt = test->settings->socket_bufsize)) {
        int saved_errno;
        if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IESETBUF;
            return -1;
        }
    }


    if ((opt = test->settings->multipath)) {
        int saved_errno;
        if (setsockopt(s, SOL_DCCP, DCCP_SOCKOPT_MULTIPATH, &opt, sizeof(opt)) < 0) {
            saved_errno = errno;
            close(s);
            freeaddrinfo(server_res);
            errno = saved_errno;
            i_errno = IEMULTIPATH;
            return -1;
        }
    }

    if (connect(s, (struct sockaddr *) server_res->ai_addr, server_res->ai_addrlen) < 0 && errno != EINPROGRESS) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(server_res);
        errno = saved_errno;
        i_errno = IESTREAMCONNECT;
        return -1;
    }

    /* Send cookie for verification */
    if (Nwrite(s, test->cookie, COOKIE_SIZE, Pdccp) < 0) {
        saved_errno = errno;
        close(s);
        freeaddrinfo(server_res);
        errno = saved_errno;
        i_errno = IESENDCOOKIE;
        return -1;
    }

    freeaddrinfo(server_res);
    return s;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}

int
iperf_dccp_init(struct iperf_test *test)
{
#if defined(HAVE_DCCP_H)
    return 0;
#else
    i_errno = IENODCCP;
    return -1;
#endif /* HAVE_DCCP_H */
}
