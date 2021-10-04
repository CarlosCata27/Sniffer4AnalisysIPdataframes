int socketRaw,aux,tramasTotales,numerotr,Clen1 = 0, Clen2 = 0, Clen3 = 0, Clen4 = 0, Clen5 = 0,ICMPv4 = 0, IGMP = 0, IP = 0, TCP = 0, UDP = 0, IPv6 = 0, OSPF = 0, OTHER = 0,TramasIPv4=0,auxtramasTotales;
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
    //for(int i = tramasTotales;i>=0;i--){
    while(tramasTotales){
        tramasTotales--;
        int n = recvfrom(sock_aux, frame_buff, 2048, 0, (struct sockaddr*)&frame_i_aux, (socklen_t*)&frame_i_len_aux);
        if(n < 0)
            printf("\nError al recibir trama - %d\n", tramasTotales);                
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
    int frameA_piv = 0;
    int Payload_size;
    int frame_frag;
    int *servicio;

    while(frameA_piv != auxtramasTotales)
    {

        //Frame y eth header
        struct ethhdr *eth_hdr;
        struct iphdr *ip_hdr;

        /* Si son frames válidas */
        if(eth_frames[frameA_piv].valida == 1)
        {            
            printf("\n-------------ANALISIS TRAMA NUM. %d-------------\n\n", frameA_piv+1);
            fprintf(Archivo, "\n-------------ANALISIS TRAMA NUM. %d-------------\n\n", frameA_piv+1);
            
            
            int print_piv  = eth_frames[frameA_piv].longitud;
            unsigned char *p = eth_frames[frameA_piv].buffer;
            /*Imprimir trama*/
            while(print_piv--)
            {
                fprintf(Archivo, "%.2X ", *p);
                p++;
            }

            printf("\n");
            fprintf(Archivo, "\n");
            
            /*Verificar frame*/
            print_piv = eth_frames[frameA_piv].longitud;
            unsigned char *new_p = eth_frames[frameA_piv].buffer;                                    
            eth_hdr = (struct ethhdr *)new_p;

            //Verificación header
            if(ntohs(eth_hdr->h_proto) == ETH_P_IP)
            {
                if(print_piv >= (sizeof(struct ethhdr)+sizeof(struct iphdr)))
                {
                    /*Contador global de tramas*/
                    TramasIPv4++;

                    //salto al ip hdr
                    ip_hdr = (struct iphdr*)(new_p+sizeof(struct ethhdr));

                    printf("Direccion IP fuente -> %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->saddr));
                    fprintf(Archivo, "Direccion IP fuente -> %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->saddr));

                    printf("Direccion IP destino ->%s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->daddr));
                    fprintf(Archivo, "Direccion IP destino -> %s\n", inet_ntoa(*(struct in_addr*)&ip_hdr->daddr));

                    printf("Longitud de cabecera en bytes -> %d Bytes \n", (unsigned int)ip_hdr->ihl*4);
                    fprintf(Archivo, "Longitud de cabecera en bytes -> %d Bytes \n", (unsigned int)ip_hdr->ihl*4);

                    printf("Longitud total del datagrama IP en bytes -> %d Bytes\n", ntohs(ip_hdr->tot_len));
                    fprintf(Archivo, "Longitud total del datagrama IP en bytes -> %d Bytes\n", ntohs(ip_hdr->tot_len));

                    printf("Identificador del datagrama -> %d\n", ntohs(ip_hdr->id));
                    fprintf(Archivo, "Identificador del datagrama -> %d\n", ntohs(ip_hdr->id));

                    printf("Tiempo de vida -> %d \n", ip_hdr->ttl);
                    fprintf(Archivo, "Tiempo de vida -> %d\n", ip_hdr->ttl);
                    int prot = ip_hdr->protocol;

                    /*Impresión protocolo de capa superior*/
                    switch (prot)
                    {
                        case 1:
                            ICMPv4++;
                            printf("Protocolo de capa superior -> 0x%.2X | ICMPv4\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | ICMPv4\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 2:
                            IGMP++;
                            printf("Protocolo de capa superior -> 0x%.2X | IGMP\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | ICMPv4\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 4:
                            IP++;
                            printf("Protocolo de capa superior -> 0x%.2X | IP\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | IP\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 6:
                            TCP++;
                            printf("Protocolo de capa superior -> 0x%.2X | TCP\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | TCP\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 11:
                            UDP++;
                            printf("Protocolo de capa superior -> 0x%.2X | UDP\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | UDP\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 29:
                            IPv6++;
                            printf("Protocolo de capa superior -> 0x%.2X | IPv6\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | IPv6\n", (unsigned int)ip_hdr->protocol);
                        break;
                        case 59:
                            OSPF++;
                            printf("Protocolo de capa superior -> 0x%.2X | OSPF\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | OSPF\n", (unsigned int)ip_hdr->protocol);
                        break;
                        default:
                            OTHER++;
                            printf("Protocolo de capa superior -> 0x%.2X | OTHER\n", (unsigned int)ip_hdr->protocol);
                            fprintf(Archivo, "Protocolo de capa superior -> 0x%.2X | OTHER\n", (unsigned int)ip_hdr->protocol);
                        break;
                    }

                    //longtotal-longheader
                    Payload_size = ntohs(ip_hdr->tot_len)-(unsigned int)ip_hdr->ihl*4;
                    printf("Longitud de carga util -> %d Bytes \n", Payload_size);
                    fprintf(Archivo, "Longitud de carga util -> %d Bytes \n", Payload_size);

                    
                    /*Paquete según tamaño*/
                    if(Payload_size >= 0 && Payload_size <= 159)
                        Clen1++;
                    if(Payload_size > 159 && Payload_size <= 639)
                        Clen2++;
                    if(Payload_size > 639 && Payload_size <= 1279)
                        Clen3++;
                    if(Payload_size > 1279 && Payload_size <= 5119)
                        Clen4++;
                    if(Payload_size >= 5120)
                        Clen5++;

                    /* Verificación para el tipo de serivicio de ip_hdr->tos */
                    int piv_tos = ip_hdr->tos;
                    int *service = malloc(sizeof(int)*(3));

                    for(int i = 0; i < 3; i++){

                        //to binary
                        //masks 0001, 0010, 0100, 1000
                        int m_aux = 1<<i;
                        //
                        int m_n = piv_tos&m_aux;

                        //to binary complementary
                        int bit = m_n>>i;
                        service[i] = bit;                        
                    }
                    printf("\n");
                     /*Verificación de servicio*/
                    switch (*service)
                    {
                        case 1:
                            //ICMPv4++;
                            printf("Tipo de servicio -> rutina\n");
                            fprintf(Archivo,"Tipo de servicio -> rutina\n");
                        break;
                        case 2:
                            //IGMP++;
                            printf("Tipo de servicio -> prioritario\n");
                            fprintf(Archivo,"Tipo de servicio -> prioritario\n");
                        break;
                        case 3:
                            //IP++;
                            printf("Tipo de servicio -> inmediato\n");
                            fprintf(Archivo,"Tipo de servicio -> inmediato\n");
                        break;
                        case 4:
                            //TCP++;
                            printf("Tipo de servicio -> relampago (flash)\n");
                            fprintf(Archivo,"Tipo de servicio -> relampago (flash)\n");
                        break;
                        case 5:
                            //UDP++;
                            printf("Tipo de servicio -> invalidacion relampago (flash override)\n");
                            fprintf(Archivo,"Tipo de servicio -> invalidacion relampago (flash override)\n");
                        break;
                        case 6:
                            //IPv6++;
                            printf("Tipo de servicio -> critico\n");
                            fprintf(Archivo,"Tipo de servicio -> critico\n");
                        break;
                        case 7:
                            //OSPF++;
                            printf("Tipo de servicio -> control de interred\n");
                            fprintf(Archivo,"Tipo de servicio -> control de interred\n");
                        break;
                        default:
                            //OTHER++;
                            printf("Tipo de servicio -> control de red\n");
                            fprintf(Archivo,"Tipo de servicio -> control de red\n");
                        break;
                    }
                    /*Verificación frame fragmentado*/
                    frame_frag = ntohs(ip_hdr->frag_off)&&IP_DF;

                    if(frame_frag == 1)
                    {
                        printf("Fragmentado -> No\n");
                        fprintf(Archivo, "Fragmentado -> No\n");
                    }
                    else if(frame_frag == 0)
                    {
                        printf("Fragmentado -> Si\n");
                        fprintf(Archivo, "Fragmentado -> Si\n");
                    }
                    if(ntohs(ip_hdr->frag_off & 0x2000) > 0)
                    {
                        if(ntohs(ip_hdr->frag_off & 0x1FFF) == 0)
                        {
                            printf("Numero de fragmento -> Primero\n");
                            fprintf(Archivo, "Numero de fragmento -> Primero\n");
                        }
                        else
                        {
                            printf("Numero de fragmento -> Intermedio\n");
                            fprintf(Archivo, "Numero de fragmento -> Intermedio\n");    
                        }
                    }
                    else
                    {
                        if(ntohs(ip_hdr->frag_off & 0x1FFF) > 0)
                        {
                            printf("Numero de fragmento -> Ultimo\n");
                            fprintf(Archivo, "Numero de fragmento -> Ultimo\n");  
                        }                    
                        else
                        {
                            printf("Numero de fragmento -> Unico\n");
                            fprintf(Archivo, "Numero de fragmento -> Unico\n");
                        }                        
                
                    }
                    /*Primer y último byte del frame*/
                    printf("1er byte del datagrama -> %.2X\n", (unsigned char)new_p[ntohs(ip_hdr->tot_len)*4+1]);
                    fprintf(Archivo, "1er byte del datagrama -> %.2X\n", (unsigned char)new_p[ntohs(ip_hdr->tot_len)*4+1]);

                    printf("Ultimo byte del datagrama -> %.2X\n", (unsigned char)new_p[print_piv]);
                    fprintf(Archivo, "Ultimo byte del datagrama -> %.2X\n", (unsigned char)new_p[print_piv]);
                }
                else
                {
                    printf("Error al analizar el frame. Cabecera no completa\n");
                    fprintf(Archivo, "Error al analizar el frame. Cabecera no completa\n");
                }
            }    
            else
            {
                //printf("No es un paquete IP\n");
                fprintf(Archivo, "No es un paquete IP\n");
            }
            frameA_piv++;
        }
    }
    pthread_exit(0);
}

