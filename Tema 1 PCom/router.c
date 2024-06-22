#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include "queue.h"
#include <string.h>
#include "lib.h"
#include <stdio.h>
#include "protocols.h"
#include <stdio.h>
static struct nod_arbore *rtable; //route_table sub forma de arbore
const uint8_t legatura[6] = {255, 255, 255, 255, 255, 255};
static struct arp_entry tabela_arp[1500]; //tabela arp
static u_int32_t dim_tabela_arp;

static queue coada_arp;
static uint32_t lungime_coada_arp;
struct nod_arbore *new_nod_arbore()
{
    struct nod_arbore *nod_nou = malloc(sizeof(struct nod_arbore));
    //aloc un nod nou
    DIE(nod_nou == NULL, "Nu exista spatiu de memorie");
    //daca nu reusesc sa il aloc
    nod_nou->left = NULL;
    nod_nou->right = NULL; //la stanga 0
    nod_nou->entry=NULL; //la dreapta 1
    return nod_nou;
}
void adauga_nod(struct route_table_entry *entry, struct nod_arbore *root)
{
    uint32_t prefix = ntohl(entry->prefix);
    uint32_t mask = ntohl(entry->mask);
    struct nod_arbore *nod_curent = root;

    // Itereaza prin fiecare bit de la 0 la 31
    for (int i = 0; i < 32; i++)
    {
        uint32_t prefix_bit = prefix & (1u << (31 - i));
        uint32_t mask_bit = mask & (1u << (31 - i));

        if (mask_bit != 0)   // Verific daca bitul e setat in masca
        {
            if (prefix_bit != 0) //daca bitul este nenul, ma duc la dreapta
            {
                if (nod_curent->right == NULL)
                    nod_curent->right = new_nod_arbore();
                nod_curent = nod_curent->right;
            }
            else //altfel, daca bitul este 0, ma duc la stanga
            {
                if (nod_curent->left == NULL)
                    nod_curent->left = new_nod_arbore();
                nod_curent = nod_curent->left;
            }
        }
    }
    nod_curent->entry = entry;
}


struct nod_arbore *cauta(struct nod_arbore *root, uint32_t ip)
{
    struct nod_arbore *nod_curent = root; //cautare incepand de la radacina
    struct nod_arbore *potrivire = NULL;
    for (int i = 31; i >= 0 && nod_curent != NULL; i--)
    {
        if (nod_curent->entry) //daca nodul curent are o intrare
            potrivire = nod_curent;
        if (ip & (1u << i))
            nod_curent = nod_curent->right;
        else
            nod_curent = nod_curent->left;
    }

    return potrivire;
}


void eliberare_memorie_arbore(struct nod_arbore *root)
{
    // Stiva pentru a tine nodurile arborelui
    struct nod_arbore **stack = malloc(sizeof(struct nod_arbore *) * 1000);
    int top = -1; // Indexul vârfului stivei

    // Verificam daca stiva a fost alocata cu succes
    if (stack == NULL)
    {
        fprintf(stderr, "Error: Nu am reusit sa aloc memorie.\n");
        exit(EXIT_FAILURE);
    }

    // Adaugam radacina arborelui in stiva
    stack[++top] = root;

    // Parcurgem arborele si eliberam fiecare nod
    while (top >= 0)
    {
        // Extragem nodul din varful stivei
        struct nod_arbore *nod_curent = stack[top--];

        // Daca nodul are un copil drept, il adaugam in stiva
        if (nod_curent->right != NULL)
            stack[++top] = nod_curent->right;

        // Daca nodul are un copil stang, il adaugam in stiva
        if (nod_curent->left != NULL)
            stack[++top] = nod_curent->left;

        // Eliberam memoria asociata nodului
        if (nod_curent->entry != NULL)
            free(nod_curent->entry);
        free(nod_curent);
    }

    // Eliberam memoria folosita pentru stiva
    free(stack);
}


struct route_table_entry *get_best_route(uint32_t destinatie)
{
    //echivalent functie get_best_hop adaptat pentru arbore
    struct nod_arbore *nod_gasit = cauta(rtable, destinatie);

    if (nod_gasit == NULL)
        return NULL;
    else
        return nod_gasit->entry; //returnez nodul gasit
}

void prepare_ip_header(struct iphdr *header_IPV4, int interfata)
{
    header_IPV4->daddr = header_IPV4->saddr; // Destinatia devine expeditorul
    header_IPV4->ttl = DEFAULT_TTL; // Resetam TTL-ul
    header_IPV4->tot_len = htons(ntohs(header_IPV4->tot_len) + ICMP_DATA_MAX_SIZE); // Modificam lungimea
    header_IPV4->saddr = inet_addr(get_interface_ip(interfata)); // Sursa devine adresa IP a interfetei
    header_IPV4->protocol = 1; // ICMP encapsulat //ICMP_PROTOCOL_NUMBER
    header_IPV4->check = 0;
    header_IPV4->check = htons(checksum((uint16_t *)header_IPV4, sizeof(struct iphdr))); // Calculam suma de control
}

// Functia pentru pregatirea antetului ICMP si adaugarea datelor
void prepare_icmp_header(struct icmphdr *header_icmp, uint8_t tip, uint8_t code, char *buffer)
{
    header_icmp->code = code; // Setam codul ICMP
    header_icmp->type = tip; // Setam tipul ICMP
    header_icmp->checksum = 0;
    header_icmp->checksum = htons(checksum((uint16_t *) header_icmp, sizeof(struct icmphdr))); // Calculam suma de control
}

// Functia pentru adaugarea datelor la pachetul ICMP
void add_icmp_data(char *buffer, size_t *lungime, struct iphdr *header_IPV4)
{
    char *data = malloc(ICMP_DATA_MAX_SIZE); //aloc dinamic datele
    memcpy(data, header_IPV4, ICMP_DATA_MAX_SIZE); //transfer in data headerul IPV4
    memcpy(ICMP_DATA_START + buffer, data, ICMP_DATA_MAX_SIZE); //pun in ICMP datele
    free(data);
    *lungime += ICMP_DATA_MAX_SIZE;
}

// Functia principala pentru mesaj ICMP
void mesaj_icmp(uint8_t tip, uint8_t code, int interfata, char *buffer, size_t *lungime)
{
    //imi definesc headere pt IPV4 si icmp
    struct iphdr *header_IPV4 = (struct iphdr *) ( IPV4_HEADER_START + buffer);
    struct icmphdr *header_icmp = (struct icmphdr *) ( ICMP_HEADER_START + buffer);

    prepare_ip_header(header_IPV4, interfata); //formatez headerul IPV4
    prepare_icmp_header(header_icmp, tip, code, buffer); //formatez icmp
    add_icmp_data(buffer, lungime, header_IPV4); //adaug datele cu ajutorul functiei
}
//apelez daca get_best_route imi returneaza NULL (nu exista cale)
void host_unreacheable(char *buffer, int interfata, size_t *lungime)
{
    mesaj_icmp(ICMP_DEST_UNREACHABLE_TYPE, ICMP_DEST_UNREACHABLE_CODE, interfata, buffer, lungime);
}
//apelez timeout cand ttl (time to live) e mai mic sau egal cu 1 
void timeout (char *buffer, int interfata, size_t *lungime)
{
    mesaj_icmp(ICMP_TIME_EXCEDEED_TYPE, ICMP_TIME_EXCEDEED_CODE,interfata, buffer, lungime);
}
void verificare_ttl_si_gestionare_timeout(struct iphdr *header_IPV4, char *buffer, int interfata, size_t *lungime)
{
    if (header_IPV4->ttl <= 1)
        timeout(buffer, interfata, lungime); //apelez timeout
}
//fac recalculare de checksum pt IPV4
void recalculare_checksum_ipv4(struct iphdr *header_IPV4)
{
    // calcul checksum
    header_IPV4->check = 0;
    header_IPV4->ttl--;
    //scad ttl
    header_IPV4->check = htons(checksum((uint16_t *)header_IPV4, sizeof(struct iphdr)));
    //recalculez checksumul

}

void gestionare_ruta_si_arp(struct iphdr *header_IPV4, struct ether_header *ethernet_header, int interfata, char *buffer, size_t lungime)
{
    struct route_table_entry *urm = get_best_route(ntohl(header_IPV4->daddr)); //gasesc urmatorul hop
    if (urm == NULL)
    {
        //daca nu gasesc urmatorul hop, apelez host_unreacheable
        host_unreacheable(buffer, interfata, &lungime);
        urm = get_best_route(ntohl(header_IPV4->daddr)); 
    }

    get_interface_mac(urm->interface, ethernet_header->ether_shost);
    int steag = 1;
    for (int k = 0; k < dim_tabela_arp; k++) //iterez prin tabela de arp
    {
        if (ntohl(tabela_arp[k].ip) == ntohl(urm->dest_urm)) //daca gasesc urmatoarea destinatie
        {
           for (int i = 0; i < 6; ++i) {
               ethernet_header->ether_dhost[i] = tabela_arp[k].mac[i];
            }
            steag = 0; //resetez steagul
            break;
        }
    }

    if (steag == 1) //daca nu am gasit o intrare in tabela arp
    {
        //creez un pachet
        struct pachet_ipv4 *pachet = malloc(sizeof(struct pachet_ipv4));
        pachet->interfata = urm->interface; //pun date in el
        pachet->next_hop = urm->dest_urm;
        pachet->lungime = lungime;
        pachet->payload = malloc(lungime + 10);
        memcpy(pachet->payload, buffer, lungime); //pun in payload bufferul
        lungime_coada_arp++;
        ethernet_header->ether_type = htons(ETHERTYPE_ARP); //tipul este 0x806
        get_interface_mac(interfata, ethernet_header->ether_shost);
       for (int len = 0; len < 6; len++) {
            ethernet_header->ether_dhost[len] = legatura[len];
        }

        struct arp_header *header_arp = malloc(sizeof(struct arp_header)); // creez un header arp
        header_arp->plen = IP_ADDRESS_LENGTH; //ii dau lungimea
        header_arp->htype = htons(ETHERNET_HARDWARE_TYPE);
        header_arp->ptype = htons(ETHERTYPE_IPV4); //ii asignez tipul
        header_arp->hlen = 6; //lungimea este de mac (6)
        queue_enq(coada_arp, (void *) pachet);
        header_arp->op = htons(ARP_REQUEST_OP); //header arp de tip request
        header_arp->spa = inet_addr(get_interface_ip(urm->interface));
        get_interface_mac(urm->interface, header_arp->sha);
        header_arp->tpa = urm->dest_urm;
        int cont = 0;
        while (cont< 6) {
            header_arp->tha[cont] = legatura[cont];
            cont++;
        }
        memcpy( sizeof(struct ether_header) + buffer, header_arp, sizeof(struct arp_header));
        lungime = sizeof(struct ether_header) + sizeof(struct arp_header);

        free(header_arp); //dau free la header
    }

    send_to_link(urm->interface, buffer, lungime); // la final trimit
}

void trimite_pachete_ipv4(char *buffer, int interfata, size_t lungime)
{
    struct iphdr *header_IPV4 = (struct iphdr *)( IPV4_HEADER_START + buffer); //header ipv4
    struct ether_header *ethernet_header = (struct ether_header *)buffer; // header ethernet

    verificare_ttl_si_gestionare_timeout(header_IPV4, buffer, interfata, &lungime); //micsorez ttl si vad daca e mai mic ca 1
    uint16_t ipv4_checksum = header_IPV4->check;
    header_IPV4->check = 0;
    // daca checksum este prost, dau drop la pachet
    if (ipv4_checksum != htons(checksum((uint16_t *)header_IPV4, sizeof(struct iphdr))))
        return;
    recalculare_checksum_ipv4(header_IPV4); //recalculez checksum
    gestionare_ruta_si_arp(header_IPV4, ethernet_header, interfata, buffer, lungime); //gestionez ruta arp
}


int main(int argc, char *argv[])
{
    dim_tabela_arp = 0;
    char buffer[MAX_PACKET_LENGTH];
    rtable = new_nod_arbore(); //aloc primul nod din rtable
    read_rtable(argv[1],rtable); //functie custom de citire de rtable
    //pun rtable intr-un arbore
    coada_arp = queue_create();
    lungime_coada_arp = 0;

    // Do not modify this line
    init(argc - 2, argv + 2);

    while (1)
    {
        int interface;
        size_t lungime;

        interface = recv_from_any_link(buffer, &lungime);
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header *header_ethernet = (struct ether_header *) buffer;
        if (header_ethernet->ether_type == ntohs(ETHERTYPE_ARP)) //daca este de tip arp
        {
            struct arp_header *header_arp = (struct arp_header *)(ARP_HEADER_START + buffer);

            if (ntohs(header_arp->op) == ARP_REQUEST_OP) 
            {
                header_arp->op = htons(ARP_REPLY_OP);

                // Copierea adresei MAC sursa in adresa MAC destinatie
                for (int i = 0; i < 6; ++i)
                {
                    header_arp->tha[i] = header_arp->sha[i];
                }

                // Obtinerea adresei MAC a interfetei si actualizarea adresei MAC sursa
                get_interface_mac(interface, header_arp->sha);

                // Actualizarea adreselor IP sursa si destinatie
                header_arp->tpa = header_arp->spa;
                header_arp->spa = inet_addr(get_interface_ip(interface));

                // Actualizarea adreselor MAC sursa si destinatie in antetul Ethernet
                struct ether_header *header_ethernet = (struct ether_header *)buffer;
                for (int i = 0; i < 6; ++i)
                {
                    header_ethernet->ether_dhost[i] = header_ethernet->ether_shost[i];
                }
                get_interface_mac(interface, header_ethernet->ether_shost);

                // Trimiterea pachetului ARP
                send_to_link(interface, buffer, lungime);
            }
            else if (ntohs(header_arp->op) == ARP_REPLY_OP)
            {
                // Gestionare raspuns ARP
                tabela_arp[dim_tabela_arp].ip = header_arp->spa;
                // Copierea datelor din header_arp->sha in tabela_arp[dim_tabela_arp].mac folosind un for
                for (int i = 0; i < 6; i++) {
                    tabela_arp[dim_tabela_arp].mac[i] = header_arp->sha[i];
                }
                dim_tabela_arp++;

                // Procesare pachete IPv4 aflate in coada si trimiterea lor
                int num_pachete_eliminate = 0;
                for (int i = 0; i < lungime_coada_arp; i++)
                {
                    struct pachet_ipv4 *ipv4_packet = (struct pachet_ipv4 *)queue_deq(coada_arp);
                    struct ether_header *header_ethernet = (struct ether_header *)ipv4_packet->payload;

                    if (ntohl(ipv4_packet->next_hop) == ntohl(header_arp->spa))
                    {
                        // Actualizare adrese MAC sursa si destinatie
                        get_interface_mac(ipv4_packet->interfata, header_ethernet->ether_shost);
                        for (int l = 0; l < 6; l++) {
                            header_ethernet->ether_dhost[l] = header_arp->sha[l];
                        }

                        // Trimitere pachet
                        send_to_link(ipv4_packet->interfata, ipv4_packet->payload, ipv4_packet->lungime);

                        // Eliberare memorie
                        free(ipv4_packet->payload);
                        free(ipv4_packet);

                        num_pachete_eliminate++;
                    }
                    else
                    {
                        // Pachetul nu este destinat interfetei pentru care am primit raspuns ARP
                        queue_enq(coada_arp, ipv4_packet);
                    }
                }
                lungime_coada_arp -= num_pachete_eliminate;
            }
        }

        else if ( header_ethernet->ether_type == ntohs(ETHERTYPE_IPV4)) //daca pachetul este IPV4
        {
            struct iphdr *header_IPV4 = (struct iphdr *) ( IPV4_HEADER_START + buffer); //definesc un nou pachet
            if (header_IPV4->daddr == inet_addr(get_interface_ip(interface)) && header_IPV4->protocol == 1)
            {
                struct iphdr *header_IPV4 = (struct iphdr *) ( IPV4_HEADER_START + buffer); //fac un header ipv4
                struct icmphdr *header_ICMP = (struct icmphdr *) ( ICMP_HEADER_START + buffer); //si unul icmp
                uint16_t calcul_checksum = header_ICMP->checksum; //calculez checksum pt ICMP

                header_ICMP->checksum = 0;
                if (htons(checksum((uint16_t *)header_ICMP, sizeof(struct icmphdr))) != calcul_checksum)
                    break; //daca checksum la header icmp e prost, dau drop la pachet
                uint32_t aux = header_IPV4->saddr; //interschimb pentru ipv4 sursa cu destinatia
                header_ICMP->type = ICMP_ECHO_REPLY_TYPE; //modific tipul icmp
                header_IPV4->saddr = header_IPV4->daddr;
                header_IPV4->daddr = aux;
                header_ICMP->code = ICMP_ECHO_CODE; //modific si codul
                //fac verificare checksum pentru IPV4
                header_IPV4->check = 0; 
                header_IPV4->check = htons(checksum((uint16_t *)header_IPV4, sizeof(struct iphdr)));
                //fac verificare checksum pentru ICMP
                header_ICMP->checksum = 0;
                header_ICMP->checksum = htons(checksum((uint16_t *)header_ICMP, sizeof(struct icmphdr)));
            }
            //trimit la final pachete ipv4
            trimite_pachete_ipv4(buffer, interface, lungime);
        }
    }
    eliberare_memorie_arbore(rtable); //eliberez memoria arborelui
    return 0;
}


