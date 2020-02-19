#include "gbn.h"
state_t s;

void alarm_handler(int sig){
	s.timeout_times++;
	if (s.timeout_times > 5){
		gbn_close(s.sockfd);
	}
	signal(SIGALRM, SIG_IGN); /* ignore same signal interrupting. */

	if (s.segment.type == SYN){
		printf("[alarm_handler]:re-send SYN...\n");
		int retval = (int)maybe_sendto(s.sockfd, &s.segment, sizeof(s.segment),0,s.addr,s.addrlen);
		if (retval < 0){
			perror("error in maybe_sendto() at gbn_connect()");
			exit(-1);
		}
	}

	if(s.segment.type == FIN){
		printf("[alarm_handler]:re-send FIN...\n");
		int retval = (int)maybe_sendto(s.sockfd, &s.segment, sizeof(s.segment),0,s.addr,s.addrlen);
		if (retval){
			perror("error in maybe_sendto() at gbn_connect()");
			exit(-1);
		}
	}

	if(s.segment.type == DATA){
        printf("[alarm_handler]: re-send DATA segment. seq_num = %d, ack_num = %d, body_len = %d.\n", s.segment.seqnum,
               s.segment.acknum, s.segment.body_len);
        if (maybe_sendto(s.sockfd, &s.segment, sizeof(s.segment), 0, s.addr, s.addrlen) < 0) {
            perror("error in sendto() at gbn_close()");
            exit(-1);
        }
        s.mode = 0; /* change to slow mode. */
    }

	signal(SIGALRM, alarm_handler);
	alarm(TIMEOUT);

}
uint16_t checksum(uint8_t *buf, int nwords)
{
	uint16_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum &(uint16_t) 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	printf("[gbn_send]: expect to send content of length = %ld. \n", len);

	int init_seq_num = s.next_expected_seq_num;
	int next_seq_num = s.next_expected_seq_num;
	int buf_ptr = 0, segment_ptr = 0;
	/*int this_window_total_data = 0;*/
	int attempts = 0;
	gbnhdr window_buffer[8];

	while(buf_ptr < len){
		int window_size = 1 << s.mode;
		int window_counter = 0;

		while (window_counter < window_size && buf_ptr < len){
			gbnhdr new_segment;
			new_segment.type = DATA;
			new_segment.seqnum = (uint32_t) next_seq_num;
			new_segment.acknum = (uint32_t) s.curr_ack_num;
			new_segment.body_len = 0;
			segment_ptr = 0;

			while(segment_ptr < DATALEN && (buf_ptr + segment_ptr) < len){
				new_segment.data[segment_ptr] = ((uint8_t *) buf)[buf_ptr + segment_ptr];
				segment_ptr++;
				new_segment.body_len++;
			}

			new_segment.checksum = checksum(new_segment.data,new_segment.body_len);
			buf_ptr += segment_ptr;
			
			if(window_counter == 0){
				s.segment = new_segment;
			}

			window_buffer[window_counter] = new_segment;
			next_seq_num = new_segment.seqnum + new_segment.body_len;
			if (attempts > MAX_ATTEMPTS){
				printf("[gbn_send]:MAX_ATTEMPTES has reached.\n");
				exit(-1);
				break;
			}else if (maybe_sendto(sockfd, &new_segment, sizeof(new_segment),0, s.addr,s.addrlen) < 0){
				printf("[gbn_send]:Unable to send DATA packet.\n");
				exit(-1);
				break;
			}else{
				printf("[gbn_send]:send one DATA segment. seq_num = %d,body_len = %d\n",new_segment.seqnum,new_segment.body_len);
				if (window_counter == 0){
					alarm(TIMEOUT);
				}
				window_counter++;
			}
			
		}
		attempts ++;
		gbnhdr received_data;
		int window_buffer_ptr = 0;

		int next_expected_ack_num = window_buffer[window_buffer_ptr].seqnum + window_buffer[window_buffer_ptr].body_len;
		int curr_window_size = 1 << s.mode ;

		while (1){
			struct sockaddr *from_addr = NULL;
			socklen_t from_len = sizeof(from_addr);
			ssize_t retval = maybe_recvfrom(sockfd, (char *) & received_data, sizeof(received_data),0,from_addr,&from_len);

			if (retval < 0){
				perror("error in recvfrom() at gbn_send()");
				if (errno != EINTR){
					printf("ERROR: Error when receive ACK.\n");
					exit(-1);
				}else{
					printf("ERROR: Timeout when receive ACK.\n");
					if (s.mode > 1){
						s.mode /= 2;
					}
					break;
				}
				
			}

			if (received_data.type == DATAACK){
				printf("[gbn_send]: received DATAACK. ack_num = %d, body_len = %d.\n", received_data.acknum,
                       received_data.body_len);
				if (received_data.seqnum == s.curr_ack_num){
					alarm(0);
					attempts = 0;
					s.timeout_times = 0;
					alarm(TIMEOUT);
					s.curr_ack_num = received_data.seqnum + s.segment.body_len;
					int old_window_buf_ptr = window_buffer_ptr;

					window_buffer_ptr ++;
					if (window_buffer_ptr < window_size){
						s.segment = window_buffer[window_buffer_ptr];
					} 
					if (s.mode < 2){
						s.mode = s.mode + 1;
					}

					s.next_expected_seq_num = received_data.acknum;

					/*if (window_buffer_ptr == curr_window_size) {
						window_buffer_ptr = 0;
					}*/

					if (window_buffer_ptr == curr_window_size || (s.curr_ack_num - init_seq_num) == len){
						break;
					}

					/*if ((s.curr_ack_num - init_seq_num) == len) {
						break;
					}*/

					/*-------------------------*/
					/*gbnhdr new_segment;
					new_segment.type = DATA;
					new_segment.seqnum = (uint32_t) next_seq_num;
					new_segment.acknum = (uint32_t) s.curr_ack_num;
					new_segment.body_len = 0;
					segment_ptr = 0;

					while(segment_ptr < DATALEN && (buf_ptr + segment_ptr) < len){
						new_segment.data[segment_ptr] = ((uint8_t *) buf)[buf_ptr + segment_ptr];
						segment_ptr++;
						new_segment.body_len++;
					}

					new_segment.checksum = checksum(new_segment.data,new_segment.body_len);
					if (maybe_sendto(sockfd, &new_segment, sizeof(new_segment),0, s.addr,s.addrlen) < 0){
						printf("[gbn_send]:Unable to send DATA packet.\n");
						exit(-1);
						break;
					}else{
						printf("[gbn_send]:send one DATA segment. seq_num = %d,body_len = %d\n",new_segment.seqnum,new_segment.body_len);
						alarm(TIMEOUT);
					}
					
					buf_ptr += segment_ptr;

					window_buffer[old_window_buf_ptr] = new_segment;
					next_seq_num = next_seq_num + new_segment.body_len;*/
					/*------------------------*/
				} else if (received_data.seqnum > s.curr_ack_num) {
					alarm(0);
					attempts = 0;
					s.timeout_times = 0;
					alarm(TIMEOUT);
					while (s.segment.seqnum < received_data.seqnum) {
						if (window_buffer_ptr < window_size){
							window_buffer_ptr ++;
							s.segment = window_buffer[window_buffer_ptr];
							printf("[gbn_send]: ENTERING THE WHILE LOOP: s.segment.segnum: %d, received_data.seqnum: %d, window_buf_ptr: %d,s.curr_ack_num:%d\n",s.segment.seqnum,received_data.seqnum,window_buffer_ptr,s.curr_ack_num);
						}
					}
					/*s.curr_ack_num = received_data.seqnum + s.segment.body_len;*/
					s.curr_ack_num = received_data.seqnum + s.segment.body_len;

					window_buffer_ptr ++;
					if (window_buffer_ptr < window_size){
						s.segment = window_buffer[window_buffer_ptr];
					} 
					if (s.mode < 2){
						s.mode = s.mode + 1;
					}

					s.next_expected_seq_num = received_data.acknum;
					if (window_buffer_ptr == curr_window_size || (s.curr_ack_num - init_seq_num) == len){
						break;
					}

				}
			}



		}
	}

	return(0);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */
while (1) {

        /* clear all old buf content. */
        int k;
        for (k = 0; k < DATALEN; k++) {
            ((uint8_t *) buf)[k] = '\0';
        }

        gbnhdr received_data;
        struct sockaddr *from_addr = NULL;
        socklen_t from_len = sizeof(from_addr);
        int retval = (int) maybe_recvfrom(sockfd, (char *) &received_data, SEGMENT_SIZE, flags, from_addr, &from_len);
        if (retval < 0) {
            perror("recvfrom in gbn_recv()");
            exit(-1);
        }
        if (received_data.type == SYN) { /* reply SYNACK. */
            printf("[gbn_recv]: receive SYN..\n");
            gbnhdr synack;
            synack.type = SYNACK;
            synack.seqnum = 1;
            synack.checksum = 0;
            maybe_sendto(sockfd, &synack, sizeof(synack), 0, s.addr, s.addrlen);
            printf("[gbn_recv]: reply SYNACK..\n");
            continue;
        }
        if (received_data.type == FIN) { /* reply FINACK. */
            printf("[gbn_recv]: receive FIN..\n");
            gbnhdr finack;
            finack.type = FINACK;
            finack.seqnum = 1;
            finack.checksum = 0;
            maybe_sendto(sockfd, &finack, sizeof(finack), 0, s.addr, s.addrlen);
            printf("[gbn_recv]: reply FINACK..\n");
            s.status = FIN_RCVD;
            return 0;
        }
        if (received_data.type == DATA) { /* reply DATAACK. */
            printf("[gbn_recv]: received one DATA segment. seq_num = %d, body_len = %d.\n", received_data.seqnum,
                   received_data.body_len);

            /* check whether the data is corrupted */
            bool passed_checksum = true;
            if (received_data.checksum != checksum(received_data.data, received_data.body_len)) {
                printf("[gbn_recv]: The data is corrupted. Checksum should be %d, but it is actually %d\n",
                       received_data.checksum, checksum(received_data.data, received_data.body_len));
                passed_checksum = false;
            } else {
                printf("[gbn_recv]: Data integrity checked.\n");
            }

            if ((s.curr_ack_num == 1 || s.curr_ack_num == received_data.seqnum) && passed_checksum) {
                /* send correct ack. */
                gbnhdr dataack;
                dataack.type = DATAACK;
                dataack.seqnum = received_data.seqnum;
                
                dataack.acknum = received_data.seqnum + received_data.body_len;
                dataack.body_len = 1; /* ACK's body_len = 1 */
                if (maybe_sendto(sockfd, &dataack, sizeof(dataack), 0, s.addr, s.addrlen)<0){
					printf("error in maybe_sento.\n");
					exit(-1);
				}
                printf("[gbn_recv]: reply DATAACK. ack_num = %d, body_len = %d.\n", dataack.acknum, dataack.body_len);

                s.curr_ack_num = dataack.acknum;
				printf("s.curr_ack_num %d ,dataack.acknum %d\n",s.curr_ack_num , dataack.acknum);
                int i;
                for (i = 0; i < received_data.body_len; i++) {
                    ((uint8_t *) buf)[i] = received_data.data[i];
                }
                printf("[gbn_recv]: write to buf. len = %d.\n", received_data.body_len);
                return (received_data.body_len);
            } else if (s.curr_ack_num > received_data.seqnum){
				gbnhdr dataack;
                dataack.type = DATAACK;
                dataack.seqnum = (uint32_t) received_data.seqnum;
                dataack.acknum = received_data.seqnum + received_data.body_len;
                dataack.body_len = 1; /* ACK's body_len = 1 */
                if (maybe_sendto(sockfd, &dataack, sizeof(dataack), 0, s.addr, s.addrlen)<0){
					printf("error in maybe_sento.\n");
					exit(-1);
				}
                printf("[gbn_recv]: reply DATAACK. ack_num = %d, body_len = %d.\n", dataack.acknum, dataack.body_len);

			} 
        }
    }
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */
	if (s.status == FIN_RCVD){
		printf("[gbn_close]:connection alredy closed.exit.\n");
		return 0;
	}
	int attempts = 0;

	while (1){
		gbnhdr fin_segment;
		fin_segment.type = FIN;
		int retval = (int) maybe_sendto(sockfd,&fin_segment,sizeof(fin_segment),0,s.addr,s.addrlen);
		if (retval < 0){
			perror("error in maybe_sendto() at close()");
			exit(-1);
		}

		s.status = FIN_SENT;
		s.segment = fin_segment;
		printf("[gbn_close]: send FIN. \n");
		alarm(TIMEOUT);

		struct sockaddr *from_addr = NULL;
		socklen_t from_len = sizeof(from_addr);
		gbnhdr buf;

		while(1){
			printf("[gbn_close]:start listening...\n");
			ssize_t retval_rec = maybe_recvfrom(sockfd,(char *) &buf, sizeof(buf),0,from_addr,&from_len);

			if (retval_rec < 0){
				perror("error in recvfrom at gbnclose()");
				exit(-1);
			}

			if (buf.type == FINACK){
				printf("[gbn_close]:received FINACK...\n");
				alarm(0);
				s.status = FIN_RCVD;
				return (close(sockfd));
			}

			if(buf.type == FIN){
				printf("[gbn_close]:receive FIN...\n");
				alarm(0);
				gbnhdr finack_segment;
				finack_segment.type = FINACK;
				fin_segment.seqnum = (uint8_t) s.seq_num;
				fin_segment.acknum = (uint8_t) s.ack_num;

				maybe_sendto(sockfd, &fin_segment,sizeof(fin_segment),0,s.addr,s.addrlen);
				printf("successfully received FIN. FINACK replied and connection closed.\n");
				s.status = FIN_RCVD;
				return (close(sockfd));
			}
		}
	}
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	s.sockfd = sockfd;
	s.seq_num = 0;
	s.ack_num = -1;
	s.data_len = 0;
	s.mode = 0;
	s.curr_ack_num = 1;
	s.next_expected_seq_num = 1;
	s.timeout_times = 0;

	signal(SIGALRM,alarm_handler);

	while (1){
		gbnhdr syn_segment;
		syn_segment.type = SYN;
		syn_segment.seqnum = (uint32_t) s.seq_num;
		syn_segment.acknum = (uint32_t) s.ack_num;

		int retval = (int) maybe_sendto(sockfd,&syn_segment,sizeof(syn_segment),0,server,socklen);
		if (retval < 0){
			perror("error in maybe_sendto() at gbn_connect");
			exit(-1);
		}
		s.segment = syn_segment;
		alarm(TIMEOUT);

		s.addr = (struct sockaddr *) server; 
		s.addrlen = socklen;

		printf("[gbn_connect]:send SYN. \n");

		gbnhdr buf;

		while (1){
			struct sockaddr *from_addr = NULL;
			socklen_t from_len = sizeof(from_addr);
			ssize_t retval2 = maybe_recvfrom(sockfd, (char *) &buf, sizeof(buf),0,from_addr,&from_len);
			if (retval2 < 0){
				perror("error in recvfrom() at gbn_connect()");
				exit(-1);
			}
			if(buf.type == SYNACK){
				alarm(0);
				printf("[gbn_connect]: received SYNACK. \n");
				return (0);
			}
		}
	}
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */
	s.curr_ack_num = 1;
	return 0;

}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	return bind(sockfd,server,socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */

	return socket(domain,type,protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	gbnhdr buf;
	while(1){
		ssize_t retval = maybe_recvfrom(sockfd,(char *) &buf, sizeof(buf),0,client,socklen );

		if (retval < 0){
			perror("error in maybe_recvfrom() at gbn_accept().");
			exit(-1);
		}

		if(buf.type == SYN){
			gbnhdr synack;
			synack.type = SYNACK;
			synack.seqnum = 1;
			synack.checksum = 0;

			ssize_t retval2 = maybe_sendto(sockfd, &synack, sizeof(synack),0,client, *socklen);
			if (retval2 < 0){
				perror("error in maybe_sendto() at gbn_accept().");
				exit(-1);
			}
			s.addr = client;
			s.addrlen = *socklen; /*--?--*/
			printf("[gbn_accept]:server successfully receive SYN and reply with SYNACK. Move to state.\n");
			break;
		}
	}
	return(sockfd);
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);
    
    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else
        return(len);  /* Simulate a success */
}
