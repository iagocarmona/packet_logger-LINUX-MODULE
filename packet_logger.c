/**
 * @file packet_logger.c
 * @author Iago Ortega Carmona
 * @author Thiago Gariani Quinto
 * @author Reginaldo Neto
 * @brief Módulo que reperesenta um logger de pacotes de rede TCP e UDP, outros pacotes não são exibidos. 
 * Desta forma, mostrando o tamanho real do pacote, o destino e a origem
 * @version 1.3
 * Data de criação: 12/11/2022
 * Data de modificação: 23/11/2022
 * 
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct nf_hook_ops *nfho;


/**
 * @brief Função utilizada para fazer as operações de receber o pacote e 
 * printar se é protocolo TCP ou UDP, mostrando seu tamanho, endereço de destino e origem.
 *
 * @param skb socket buffer
 * @return unsigned int 
 */
static unsigned int hfunc(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph; //struct que contém o cabeçalho de rede

	if (!skb) // se o buffer está vazio, deixa o pacote continuar seu roteamento.
		return NF_ACCEPT;

 	iph = ip_hdr(skb); // pega o header do protocolo IP

	if (iph->protocol == IPPROTO_UDP) { // se o pacote ser do protocolo UDP, suas informações são exibidas
		pr_info("PLOG [UDP] SIZE: %x, SOURCE ADDRESS: %x, DESTINATION ADDRESS: %x\n", skb->truesize, iph->saddr, iph->daddr);
	}else if (iph->protocol == IPPROTO_TCP) { // se o pacote ser do protocolo TCP, suas informações são exibidas
		pr_info("PLOG [TCP] SIZE: %x, SOURCE ADDRESS: %x, DESTINATION ADDRESS: %x\n", skb->truesize, iph->saddr, iph->daddr);
	}

	return NF_ACCEPT;
}

/**
 * @brief Função responsável por inicializar o módulo, sendo assim, inicializando a estrutura 
 * com os valores pra receber os pacotes.
 * 
 * @return int 
 */
static int __init packet_logger_init(void)
{
	nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	
	/* Initialize netfilter hook */
	nfho->hook 	= (nf_hookfn*)hfunc;		/* hook function */
	nfho->hooknum 	= NF_INET_PRE_ROUTING;		/* received packets */
	nfho->pf 	= PF_INET;			/* IPv4 */
	nfho->priority 	= NF_IP_PRI_FIRST;		/* max hook priority */
	
	nf_register_net_hook(&init_net, nfho);

	return 0;
}

/**
 * @brief Esta função é responsável por desalocar as estruturas utilizadas.
 * 
 */
static void __exit packet_logger_exit(void)
{
	nf_unregister_net_hook(&init_net, nfho);
	kfree(nfho);
}

module_init(packet_logger_init); //inicializa o módulo chamando a função que será realizada
module_exit(packet_logger_exit); //termina o módulo chamando a função correspondente com esssa ação
 
MODULE_LICENSE("GPL"); 
MODULE_VERSION("1.3");
MODULE_AUTHOR("Iago Carmona, Thiago Gariani Quinto, Reginaldo Neto"); 
MODULE_DESCRIPTION("Este módulo é um logger de pacotes de rede TCP e UDP, outros pacotes não são exibidos. Desta forma, mostrando o tamanho real do pacote, o destino e a origem"); 