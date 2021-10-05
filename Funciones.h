int socketRaw,aux,tramasTotales,numerotr,Packetlen1 = 0, Packetlen2 = 0, Packetlen3 = 0, Packetlen4 = 0, Packetlen5 = 0,ICMPv4 = 0, IGMP = 0, IP = 0, TCP = 0, UDP = 0, IPv6 = 0, OSPF = 0,TramasIPv4=0,auxtramasTotales,i=0,impresionIPaux = 0,direccionIP = 0, visitado = 0,j=0,k=0;
FILE *Archivo;
struct iphdr *addr_ip_hdr;
struct sockaddr_in addr_dest, addr_src;
pthread_t thread1, thread2;
pthread_attr_t thread_att;

struct addresses{
	struct sockaddr_in addr;	
	int count_send;
    int count_rec;
};

//Estructura para almacenar tramas, longitud y validez
typedef struct{
  unsigned char buffer[2048];
  int longitud;
  int valida;

}Tramas;

struct addresses *addr;
Tramas *eth_frames;

/* Verificar protocolo */
int ValidadordeProtocolo(unsigned char *header){
    int Resultado = 0;
    struct ethhdr *eth_hdr;
	struct iphdr *ip_hdr;
    eth_hdr =  (struct ethhdr *)header;
    if(ntohs(eth_hdr->h_proto) == ETH_P_IP){
		ip_hdr = (struct iphdr *)(header+sizeof(struct ethhdr));
		if(ip_hdr->protocol == IPPROTO_TCP)
            Resultado =  1;	
	}
    return Resultado;
}

void *CapturadeTramas(void *arg){
    struct sockaddr_ll frame_i_aux;
    int frame_i_len_aux = sizeof(frame_i_aux),ValidacionIP;
    unsigned char frame_buff[2048];
    Tramas eth_hdr;
    int sock_aux = *(int *)arg;
    //Se recorren todas las tramas solicitadas
    
    while(tramasTotales){
        tramasTotales--;
        int n = recvfrom(sock_aux, frame_buff, 2048, 0, (struct sockaddr*)&frame_i_aux, (socklen_t*)&frame_i_len_aux);
        if(n < 0)
            fprintf(Archivo,"\nError al recibir trama - %d\n", tramasTotales);                
        else{
            //Verificacion de que el tamaño sea valido
            if(n > sizeof(struct ethhdr)){
                ValidacionIP = ValidadordeProtocolo(frame_buff);
                //Si no es la direccion IP que solicitamos
                if(ValidacionIP != 1)
                    tramasTotales++;
                else{
                    memcpy(eth_frames[tramasTotales].buffer, frame_buff, 2048);
                    eth_frames[tramasTotales].longitud = n;
                    eth_frames[tramasTotales].valida = 1;
                }
            }
        }
    }
    pthread_exit(0);
}

void *AnalisisdeTrama(void *arg){
    int auxtramaAnalizada = 0,flagTrama,tamañoTrama;
    while(auxtramaAnalizada != auxtramasTotales)
    {
        struct ethhdr *eth_hdr;
        struct iphdr *ip_hdr;

        //Verificamos que las tramas sean validas para analizar
        if(eth_frames[auxtramaAnalizada].valida == 1)
        {            
            fprintf(Archivo, "Analizando trama -- %d --\n", auxtramaAnalizada+1);
            
            int impresionTrama = eth_frames[auxtramaAnalizada].longitud;
            unsigned char *p = eth_frames[auxtramaAnalizada].buffer;                                    
            eth_hdr = (struct ethhdr *)p;

            //Verificación del header
            if(ntohs(eth_hdr->h_proto) == ETH_P_IP){
                if(impresionTrama >= (sizeof(struct ethhdr)+sizeof(struct iphdr))){
                    TramasIPv4++;
                    //Analisis del header
                    ip_hdr = (struct iphdr*)(p+sizeof(struct ethhdr));

                    fprintf(Archivo,"Direccion IP de fuente: %s\t",inet_ntoa(*(struct in_addr*)&ip_hdr->saddr));
                    fprintf(Archivo,"Direccion IP de destino: %s\n",inet_ntoa(*(struct in_addr*)&ip_hdr->daddr));
                    fprintf(Archivo, "Longitud de cabecera: %d Bytes  \tLongitud total del datagrama IP: %d Bytes\n", (unsigned int)ip_hdr->ihl*4,ntohs(ip_hdr->tot_len));
                    fprintf(Archivo,"Identificador del datagrama: %d\tTTL: %d \n", ntohs(ip_hdr->id),ip_hdr->ttl);

                    int tipoProtocolo = ip_hdr->protocol;
                    //Impresion del tipo de protocolo de capa superior
                    if(tipoProtocolo ==1){
                        ICMPv4++;
                        fprintf(Archivo, "Protocolo de capa superior ICMPv4: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo ==2){
                        IGMP++;
                        fprintf(Archivo, "Protocolo de capa superior IGMP: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo ==4){
                        IP++;
                        fprintf(Archivo, "Protocolo de capa superior IP: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo==6){
                        TCP++;
                        fprintf(Archivo, "Protocolo de capa superior TCP: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo==11){
                        UDP++;
                        fprintf(Archivo, "Protocolo de capa superior UDP: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo==29){
                        IPv6++;
                        fprintf(Archivo, "Protocolo de capa superior IPv6: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else if(tipoProtocolo==59){
                        OSPF++;
                        fprintf(Archivo, "Protocolo de capa superior OSPF: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    }else
                        fprintf(Archivo, "Protocolo de capa superior OTRO TIPO: 0x%.2X\t", (unsigned int)ip_hdr->protocol);
                    

                    //Longitud de carga util
                    tamañoTrama = ntohs(ip_hdr->tot_len)-(unsigned int)ip_hdr->ihl*4;
                    fprintf(Archivo, "Longitud de carga util: %d Bytes \n", tamañoTrama);

                    //Clasificacion del tamaño del paquete
                    if(tamañoTrama >= 0 && tamañoTrama <= 159)
                        Packetlen1++;
                    if(tamañoTrama > 159 && tamañoTrama <= 639)
                        Packetlen2++;
                    if(tamañoTrama > 639 && tamañoTrama <= 1279)
                        Packetlen3++;
                    if(tamañoTrama > 1279 && tamañoTrama <= 5119)
                        Packetlen4++;
                    if(tamañoTrama >= 5120)
                        Packetlen5++;

                    int auxtipoServicio = ip_hdr->tos;
                    int *tipoServicio = malloc(sizeof(int)*(3));

                    for(int i = 0; i < 3; i++){
                        int m_aux = 1<<i;
                        int m_n = auxtipoServicio&m_aux;
                        int bit = m_n>>i;
                        tipoServicio[i] = bit;                        
                    }
                     //Verificación del tipo de servicio
                    if(*tipoServicio ==0)
                        fprintf(Archivo,"Tipo de servicio: Rutina\n");
                    else if(*tipoServicio ==1)
                        fprintf(Archivo,"Tipo de servicio: Prioritario\n");
                    else if(*tipoServicio ==2)
                        fprintf(Archivo,"Tipo de servicio: Inmediato\n");
                    else if(*tipoServicio ==3)
                        fprintf(Archivo,"Tipo de servicio: Relampago (flash)\n");
                    else if(*tipoServicio ==4)
                        fprintf(Archivo,"Tipo de servicio: Invalidacion relampago (flash override)\n");
                    else if(*tipoServicio ==5)
                        fprintf(Archivo,"Tipo de servicio: Critico\n");
                    else if(*tipoServicio ==6)
                        fprintf(Archivo,"Tipo de servicio: Control de interred\n");
                    else if(*tipoServicio ==7)
                        fprintf(Archivo,"Tipo de servicio: Control de red\n");
                    
                    //Verificacion de la fragmentacion de la trama
                    flagTrama = ntohs(ip_hdr->frag_off)&&IP_DF;

                    if(flagTrama == 1)
                        fprintf(Archivo, "Fragmentado: No\n");
                    else if(flagTrama == 0){
                        fprintf(Archivo, "Fragmentado: Si  \t");

                        if(ntohs(ip_hdr->frag_off & 0x2000) > 0)
                            if(ntohs(ip_hdr->frag_off & 0x1FFF) == 0)
                                fprintf(Archivo, "Numero de fragmento: Primero\n");
                            else
                                fprintf(Archivo, "Numero de fragmento: Intermedio\n");    
                        else
                            if(ntohs(ip_hdr->frag_off & 0x1FFF) > 0)
                                fprintf(Archivo, "Numero de fragmento: Ultimo\n");  
                            else
                                fprintf(Archivo, "Numero de fragmento: Unico\n");
                    }
                    //Primer y ultimo byte del datagrama
                    fprintf(Archivo,"Primer byte del datagrama: %.2X\tUltimo byte del datagrama: %.2X\n\n", (unsigned char)p[ntohs(ip_hdr->tot_len)*4+1],(unsigned char)p[impresionTrama]);
                }else
                    fprintf(Archivo, "Error al analizar el frame. Cabecera no completa\n");
                
            }else
                fprintf(Archivo, "No es un paquete IP\n");
            auxtramaAnalizada++;
        }
    }
    pthread_exit(0);
}

void Resultados(){
    fprintf(Archivo,"--Resultados finales--\n");
    fprintf(Archivo, "Total de tramas IPv4: %d\n", TramasIPv4);
    fprintf(Archivo, "\nTramas analizadas de cada protocolo\n");
    fprintf(Archivo,"\tICMPv4: %d\n\tIGMP: %d\n\tIP: %d\n\tTCP: %d\n\tUDP: %d\n\tIPv6: %d\n\tOSPF: %d\n",ICMPv4, IGMP, IP, TCP, UDP, IPv6, OSPF);
  
    unsigned char *addr_p = eth_frames[0].buffer;
    addr = malloc(auxtramasTotales*sizeof(struct addresses));
    
    while(i<auxtramasTotales){
        addr_p = eth_frames[i].buffer;
        addr_ip_hdr = (struct iphdr*)(addr_p+sizeof(struct ethhdr));
        memset(&addr_dest, 0, sizeof(addr_dest));
        memset(&addr_src, 0, sizeof(addr_src));
        addr_dest.sin_addr.s_addr = addr_ip_hdr->daddr;
        addr_src.sin_addr.s_addr = addr_ip_hdr->saddr;

        //Se verifican cada una de las direcciones guardadas
        if(direccionIP > 0 ){
             //Verificacion de si la direccion es igual a la fuente de la siguiente direccion
            for (int j = 0; j < direccionIP; j++){
                if(addr[j].addr.sin_addr.s_addr == addr_src.sin_addr.s_addr){
                    visitado = 1;
                    addr[j].count_send++;                    
                    break;
                }
            }

            if(visitado != 0)
                visitado = 0;                
            else{
                //Si la direccion enviada es nueva se guarda
                addr[direccionIP].addr.sin_addr.s_addr = addr_src.sin_addr.s_addr;                
                addr[direccionIP].count_rec = 0;
                addr[direccionIP].count_send = 1;
                direccionIP++;
            }

            for (int k = 0; k < direccionIP; k++)
                if(addr[k].addr.sin_addr.s_addr == addr_dest.sin_addr.s_addr){
                    visitado = 1;
                    addr[k].count_rec++;                    
                    break;
                }
            
            if(visitado != 0)
                visitado = 0;                
            else{
                //Si la direccion recibida es nueva esta se guarda
                addr[direccionIP].addr.sin_addr.s_addr = addr_dest.sin_addr.s_addr;                
                addr[direccionIP].count_rec = 1;
                addr[direccionIP].count_send = 0;
                direccionIP++;
            }
        }else{
            addr[0].addr.sin_addr.s_addr = addr_src.sin_addr.s_addr;            
            addr[0].count_rec = 0;
            addr[0].count_send = 1;
            addr[1].addr.sin_addr.s_addr = addr_dest.sin_addr.s_addr;
            addr[1].count_rec = 1; 
            addr[1].count_send = 0;
            direccionIP+=2;           
        }
        i++;
    }
    fprintf(Archivo, "\nTotal de tramas transmitidas y recibidas por direccion\n");
    fprintf(Archivo,"Total de direcciones: %d\n", direccionIP);

    while(impresionIPaux < direccionIP){
        fprintf(Archivo,"\nDireccion #%d\n", impresionIPaux+1);
        fprintf(Archivo, "\tIP: %s\n", inet_ntoa(addr[impresionIPaux].addr.sin_addr));
        fprintf(Archivo, "\tTransmitidas: %d\n", addr[impresionIPaux].count_send);
        fprintf(Archivo, "\tRecibidas: %d\n", addr[impresionIPaux].count_rec);
        impresionIPaux++;
    }
    fprintf(Archivo, "\nTotal de tramas por tamaño\n");
    fprintf(Archivo, "\t0 - 159: %d\n\t160 - 639: %d\n\t640 - 1279: %d\n\t1280 - 5119: %d\n\t5120 o más: %d\n",Packetlen1,Packetlen2,Packetlen3,Packetlen4,Packetlen5);
}