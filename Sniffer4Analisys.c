#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <features.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "Funciones.h"

int main(int argc, char *argv[]){
    tramasTotales =0; aux =0;
    tramasTotales = atoi(argv[2]);
    auxtramasTotales = tramasTotales;

    //Reservacion de memoria para el analisis de las tramas
    eth_frames = malloc(tramasTotales*sizeof(Tramas));
    if(eth_frames == NULL){
        printf("\nError al momento de reservar memoria\n");
        exit(1);
    }

    //Creacion del socket
    pthread_attr_init(&thread_att);
    pthread_attr_setdetachstate(&thread_att, PTHREAD_CREATE_JOINABLE);
    socketRaw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if(socketRaw < 0){
        fprintf(Archivo,"\nError al crear socket\n");
        exit(1);
    }

    //Modo promiscuo tarjeta
    struct ifreq eth;
    bzero(&eth, sizeof(eth));
    strncpy((char *)eth.ifr_name, argv[1], IFNAMSIZ);
    ioctl(socketRaw, SIOCGIFFLAGS, &eth);
    // Modo promiscuo de la tarjeta de red
    eth.ifr_flags |= IFF_PROMISC;
    ioctl(socketRaw, SIOCGIFFLAGS, &eth);
    if(socketRaw < 0){
        fprintf(Archivo,"Error en bind del socket y tarjeta de red");
        exit(1);        
    }

    Archivo = fopen("Analisis_de_tramas.txt", "w+");
    if(Archivo == NULL){
        fprintf(Archivo,"\nError al crear el fichero\n");
        exit(1);
    }
    pthread_create(&thread1, &thread_att, CapturadeTramas, (void *)&socketRaw);
    pthread_create(&thread2, &thread_att, AnalisisdeTrama, (void *)&socketRaw);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    //fclose(Archivo);
    return 0;
}