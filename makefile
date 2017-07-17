all : pcap_my

pcap_my : pcap_exercise.o

			gcc -o pcap_my pcap_exercise.o -lpcap

pcap_exercise.o : pcap_exercise.c

			gcc -c -o pcap_exercise.o pcap_exercise.c -lpcap

clean :

			rm -rf *.o pcap_my
