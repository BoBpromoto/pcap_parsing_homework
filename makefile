all : pcap_my

pcap_my : pcap_exercise_170724.o

			gcc -o pcap_my pcap_exercise_170724.o -lpcap

pcap_exercise.o : pcap_exercise_170724.c

			gcc -c -o pcap_exercise_170724.o pcap_exercise_170724.c -lpcap

clean :

			rm -rf *.o pcap_my
