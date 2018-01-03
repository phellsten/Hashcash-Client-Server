// Paul Hellsten - 758077
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <math.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include "uint256.h"
#include "sha256.h"

void *interpretMessage(void *param);

int num_threads = 0, sockfd, newsockfd, portno, clilen;
char message[256], str[INET_ADDRSTRLEN];
int testn = 0;
struct sockaddr_in serv_addr, cli_addr;
FILE *f;
time_t mytime;

int main(int argc, char **argv) {
	// Create log file
	f  = fopen("log.txt", "w");
	if (f == NULL) {
	    printf("Error opening file!\n");
	    exit(1);
	}
	if (argc < 2) {
		fprintf(stdout,"ERROR, no port provided\n");
		exit(1);
	}

	// Create TCP socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));

	portno = atoi(argv[1]);

	/* Create address we're going to listen on (given port number)
	 - converted to network byte order & any IP address for
	 this machine */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);  // store in machine-neutral format

	 /* Bind address to the socket */
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR on binding");
		exit(1);
	}

	/* Listen on socket - means we're ready to accept connections -
	 incoming connection requests will be queued */
	listen(sockfd,5);
	clilen = sizeof(cli_addr);

  while (newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen)) {
    int *sockptr = malloc(sizeof(int*));
    *sockptr = newsockfd;
		pthread_t newthread;

		if(num_threads >= 100) {
			perror("maximum clients reached");
		}
		else {
			// Create a new thread for the new client
			if(pthread_create(&newthread, NULL, interpretMessage, (void *)sockptr)) {
	      perror("could not create thread");
	      return 1;
	    }
		}
  }

  if (newsockfd < 0) {
    perror("accept failed");
    return 1;
  }

  close(sockfd);
	fclose(f);
  return 0;
}
void *interpretMessage(void *param) {
  char buffer[256];
  char message[256];
	bzero(buffer, 256);
	bzero(message, 256);
  int n;
  int newsockfd = *(int*) param;
  int msize = 0;
	num_threads++;

  while(1) {
    while(1) {
			// Read in 1 byte from file
      bzero(buffer,256);
      n = read(newsockfd,buffer,1);
      if (n < 0){
    		perror("ERROR reading from socket");
        close(newsockfd);
        num_threads--;
        pthread_exit(NULL);
				return 0;
    	}

      if(n == 0) {
        perror("ERROR client terminated");
        close(newsockfd);
        num_threads--;
        pthread_exit(NULL);
				return 0;
      }

      strcat(message, buffer);
      int msize = strlen(message);

      if(msize > 100) {
        bzero(message, 256);
				char response[45];
				bzero(response, 45);
	      strcpy(response, "ERRO Message is too long                   \r\n");
				n = write(newsockfd, response, 45);
				mytime = time(NULL);
				char* s = ctime(&mytime);
				s[strlen(s)-1] = '\0';
				fprintf(f, "%s %s (%d): Response  - %s", s, str, newsockfd, response);
				fflush(f);
        continue;
      }

      if(strncmp("\r\n", &message[msize-2], 2) == 0 ) {
        // found a complete message
        // lets check it out
        break;
      }
    }
    msize = strlen(message);

		// Log client IP
		inet_ntop(cli_addr.sin_family, &cli_addr.sin_addr, str, INET_ADDRSTRLEN );
		mytime = time(NULL);
		char* s = ctime(&mytime);
		s[strlen(s)-1] = '\0';
		fprintf(f, "%s %s (%d): Message  - %s", s, str, newsockfd, message);
		fflush(f);

		// Got PING, Respond with PONG
    if(strncmp(message, "PING\r\n", 6) == 0) {
      bzero(message, 256);
      char presponse[6];
			bzero(presponse, 6);
			strcpy(presponse, "PONG\r\n");
			n = write(newsockfd, presponse, 6);
			mytime = time(NULL);
			char* s = ctime(&mytime);
			s[strlen(s)-1] = '\0';
			fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, presponse);
			fflush(f);
    }
		// Got PONG, Respond with ERRO
    else if(strncmp("PONG\r\n", message, 6) == 0) {
      bzero(message, 256);
			char response[45];
			bzero(response, 45);
      strcpy(response, "ERRO PONG reserved for server use only     \r\n");
      n = write(newsockfd, response, 45);
			mytime = time(NULL);
			char* s = ctime(&mytime);
			s[strlen(s)-1] = '\0';
			fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
			fflush(f);
    }
		// Got OKAY, Respond with ERRO
    else if(strncmp("OKAY\r\n", message, 6) == 0) {
			bzero(message, 256);
			char response[45];
			bzero(response, 45);
      strcpy(response, "ERRO it is not okay to send OKAY           \r\n");
      n = write(newsockfd, response, 45);
			mytime = time(NULL);
			char* s = ctime(&mytime);
			s[strlen(s)-1] = '\0';
			fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
			fflush(f);
    }
		// Got ERRO, Respond with ERRO
    else if(strncmp("ERRO\r\n", message, 6) == 0) {
			bzero(message, 256);
			char response[45];
			bzero(response, 45);
      strcpy(response, "ERRO no ERRO messages allowed              \r\n");
      n = write(newsockfd, response, 45);
			mytime = time(NULL);
			char* s = ctime(&mytime);
			s[strlen(s)-1] = '\0';
			fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
			fflush(f);
    }
		// Got SOLN, Compute hash
    else if(strncmp("SOLN", message, 4) == 0) {
      if(msize == 97) {
        uint32_t difficulty;
        char difficultystring[9], seedstring[65], solutionstring[17];
        int pos = 5, i = 0;
				// Parse difficulty
        for(; pos < 13; pos++) {
          difficultystring[i] = message[pos];
          i++;
        }
        difficultystring[i] = '\0';

        i = 0;
        pos++;
				// Parse seed
        for(; pos < 78; pos++) {
          seedstring[i] = message[pos];
          i++;
        }
        seedstring[i] = '\0';

        BYTE seed[32];
        uint256_init(seed);

        i =0;
        int ccount = 0;
        char buf[10];
				// Convert seed to BYTE array
        for(i=0; i < 64; i+=2) {
          sprintf(buf, "0x%c%c", seedstring[i], seedstring[i+1]);
          seed[ccount] = strtol(buf, NULL, 0);
          ccount++;
        }

        i = 0;
        pos++;
				// Parse solution
        for(; pos < 95; pos++) {
          solutionstring[i] = message[pos];
          i++;
        }

        solutionstring[i] = '\0';

        difficulty = strtoul(difficultystring, NULL, 16);

        uint32_t alpha, beta;

        alpha = difficulty;
				// Shift right 24 to get first 8 bits
        alpha = difficulty >> 24;
				// Shift left 8 and back 8 to zero first 8 bits
        beta = difficulty << 8 >> 8;

        BYTE target[32];
        uint256_init(target);

        alpha -= 3;
        alpha *= 8;

        BYTE base[32];
        uint256_init(base);
        base[31] = 0x02;
				// Compute exponent of target
        uint256_exp(target, base, alpha);

				// Concatenate together seed and solution
        BYTE concatseedsol[40];
        for(size_t i=0; i < 32; i++) {
          concatseedsol[i] = seed[i];
        }
        for(size_t i=32; i < 40; i++) {
          concatseedsol[i] = 0;
        }
        ccount = 32;
        for(i=0; i < 16; i+=2) {
          sprintf(buf, "0x%c%c", solutionstring[i], solutionstring[i+1]);
          concatseedsol[ccount] = strtol(buf, NULL, 0);
          ccount++;
        }

				// Perform double hash
        SHA256_CTX ctx;
        BYTE bf[SHA256_BLOCK_SIZE], bf2[SHA256_BLOCK_SIZE];
        sha256_init(&ctx);
        sha256_update(&ctx, concatseedsol, sizeof(concatseedsol));
        sha256_final(&ctx, bf);
        sha256_init(&ctx);
        sha256_update(&ctx, bf, sizeof(bf));
        sha256_final(&ctx, bf2);

        BYTE uint256beta[32];
        uint256_init(uint256beta);
				// Convert beta to BYTE array
        uint256beta[28] = (int)((beta >> 24) & 0xFF);
        uint256beta[29] = (int)((beta >> 16) & 0xFF);
        uint256beta[30] = (int)((beta >> 8) & 0xFF);
        uint256beta[31] = (int)(beta & 0xFF);

        uint256_mul(target, target, uint256beta);

				// See if we've got the right solution
        if(sha256_compare(bf2, target) == 1) {
					bzero(message, 256);
					char response[45];
					bzero(response, 45);
		      strcpy(response, "ERRO not a valid proof of work             \r\n");
          n = write(newsockfd, response, 45);
					mytime = time(NULL);
					char* s = ctime(&mytime);
					s[strlen(s)-1] = '\0';
					fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
					fflush(f);
        }
        else {
          bzero(message, 256);
          char oresponse[6];
					bzero(oresponse, 6);
					strcpy(oresponse, "OKAY\r\n");
          n = write(newsockfd, oresponse, 6);
          fprintf(stdout, "wrote: '%s'", oresponse);
					mytime = time(NULL);
					char* s = ctime(&mytime);
					s[strlen(s)-1] = '\0';
					fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, oresponse);
					fflush(f);
        }
      }
      else {
				bzero(message, 256);
				char response[45];
				bzero(response, 45);
	      strcpy(response, "ERRO malformed SOLN message                \r\n");
        n = write(newsockfd, response, 45);
				mytime = time(NULL);
				char* s = ctime(&mytime);
				s[strlen(s)-1] = '\0';
				fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
				fflush(f);
      }
    }
		// Got WORK, Compute a valid SOLN
    else if(strncmp("WORK ", message, 5) == 0) {
      if(msize == 100) {
        uint32_t difficulty, alpha, beta;
        char difficultystring[9], seedstring[65], solutionstring[17],
					buf[10];
        int pos = 5, i = 0, ccount = 0;// nthreads;
				BYTE seed[32], target[32], base[32], uint256beta[32], concatseedsol[40];

				uint256_init(seed);
				uint256_init(target);
				uint256_init(base);
				uint256_init(uint256beta);

				if(message[13] != ' ' || message[78] != ' ' || message[95] != ' ') {
					bzero(message,256);
					char response[46] = "ERRO malformed WORK message                \r\n\0";
					n = write(newsockfd, response, 45);
					mytime = time(NULL);
					char* s = ctime(&mytime);
					s[strlen(s)-1] = '\0';
					fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
					fflush(f);
				}
				else {
					// Valid message, create a new thread to repsond to
					// other client messages
					int *sockptr = malloc(sizeof(int*));
			    *sockptr = newsockfd;
					pthread_t newthread;
			    if(pthread_create(&newthread, NULL, interpretMessage, (void *)sockptr)) {
			      perror("could not create thread");
			      return 0;
			    }

	        for(; pos < 13; pos++) {
	          difficultystring[i] = message[pos];
	          i++;
	        }
	        difficultystring[i] = '\0';

	        i = 0;
	        pos++;
	        for(; pos < 78; pos++) {
	          seedstring[i] = message[pos];
	          i++;
	        }
	        seedstring[i] = '\0';

	        i = 0;
	        for(i=0; i < 64; i+=2) {
	          sprintf(buf, "0x%c%c", seedstring[i], seedstring[i+1]);
	          seed[ccount] = strtol(buf, NULL, 0);
	          ccount++;
	        }

	        i = 0;
	        pos++;
	        for(; pos < 95; pos++) {
	          solutionstring[i] = message[pos];
	          i++;
	        }
	        solutionstring[i] = '\0';

	        i=0;
	        pos++;

	        difficulty = strtoul(difficultystring, NULL, 16);

	        alpha = difficulty;
	        alpha = difficulty >> 24;
	        beta = difficulty << 8 >> 8;

	        alpha -= 3;
	        alpha *= 8;

	        base[31] = 0x02;

	        uint256_exp(target, base, alpha);

	        uint256beta[28] = (int)((beta >> 24) & 0xFF);
	        uint256beta[29] = (int)((beta >> 16) & 0xFF);
	        uint256beta[30] = (int)((beta >> 8) & 0xFF);
	        uint256beta[31] = (int)(beta & 0xFF);

	        uint256_mul(target, target, uint256beta);

	        for(size_t i=0; i < 32; i++) {
	          concatseedsol[i] = seed[i];
	        }
	        for(size_t i=32; i < 40; i++) {
	          concatseedsol[i] = 0;
	        }

	        for(i=0; i < 16; i+=2) {
	          sprintf(buf, "0x%c%c", solutionstring[i], solutionstring[i+1]);
	          concatseedsol[ccount] = strtol(buf, NULL, 0);
	          ccount++;
	        }

	        while(1) {
	          ccount = 32;
	          bzero(buf, 10 );

	          SHA256_CTX ctx;
	          BYTE bf[SHA256_BLOCK_SIZE], bf2[SHA256_BLOCK_SIZE];
	          sha256_init(&ctx);
	          sha256_update(&ctx, concatseedsol, sizeof(concatseedsol));
	          sha256_final(&ctx, bf);
	          sha256_init(&ctx);
	          sha256_update(&ctx, bf, sizeof(bf));
	          sha256_final(&ctx, bf2);

	          if(sha256_compare(bf2, target) == -1) {
							// Found a solution
	            char returnmessage[97];
	            bzero(returnmessage, 97);
							strcat(returnmessage, "SOLN ");
							strcat(returnmessage, difficultystring);
							strcat(returnmessage, " ");
							strcat(returnmessage, seedstring);
							strcat(returnmessage, " ");

	            char temp[18];
	            char newnonce[18];
	            bzero(temp, 16);
	            bzero(newnonce, 16);
	            for(size_t i=32; i <= 40; i+=1) {
	              sprintf(temp, "%02x", concatseedsol[i]);
	              strcat(newnonce, temp);
	            }
	            newnonce[16] = '\0';

	            strcat(returnmessage, newnonce);
							strcat(returnmessage, "\r\n\0");

	            bzero(message,256);
	            n = write(newsockfd, returnmessage, 96);

							mytime = time(NULL);
							char* s = ctime(&mytime);
							s[strlen(s)-1] = '\0';
							fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, returnmessage);
							fflush(f);
	            break;
	          }
	          else {
							char buffer[32];
							// Check if client is still connected
							if(recv(newsockfd, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0) {
								// Client has terminated, stop attempting to find solution.
								close(newsockfd);
								pthread_exit(NULL);
								return 0;
							}

	            BYTE add[40];
	            uint256_init(base);
	            add[39] = 0x01;

	            BYTE aa[40], bb[40];
	            uint256_init (aa);
	            uint256_init (bb);

	            memcpy (aa, add, 40);
	            memcpy (bb, concatseedsol, 40);
	            uint16_t temp = 0;
	            for (int i = 39; i > 31; i--) {
	              temp >>= 8;
	              temp += aa[i];
	              temp += bb[i];
	              concatseedsol[i] = (BYTE) (temp & 0xff);
	          	}
	          }
	        }
					//pthread_join(newthread, NULL);
					pthread_exit(NULL);
				}
      }
      else {
        bzero(message,256);
        char response[46] = "ERRO malformed WORK message                \r\n\0";
        n = write(newsockfd, response, 45);
				mytime = time(NULL);
				char* s = ctime(&mytime);
				s[strlen(s)-1] = '\0';
				fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
				fflush(f);
      }
    }
    else {
      bzero(message,256);
      char response[46] = "ERRO unknown message recieved              \r\n\0";
      n = write(newsockfd, response, 45);
			mytime = time(NULL);
			char* s = ctime(&mytime);
			s[strlen(s)-1] = '\0';
			fprintf(f, "%s 0.0.0.0 (%d): Response  - %s", s, newsockfd, response);
			fflush(f);

    }

    if (n < 0) {
      perror("ERROR writing to socket");
      close(newsockfd);
      num_threads--;
      pthread_exit(NULL);
    }
  }
  num_threads--;
  close(newsockfd);
  pthread_exit(NULL);
}
