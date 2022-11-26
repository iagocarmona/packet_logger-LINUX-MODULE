Instalação do módulo:
Para realizar a preparação do módulo, ou seja, a criação dos arquivos, digite o comando make no terminal. Após realizar o passo citado,
para realizar a instalação do módulo, digite sudo insmod packet_logger.ko.
Em seguida para visualizar os pacotes TCP e UDP sendo recebidos, digite sudo dmesg -wH | grep PLOG, no terminal.  O sudo digitado nos últimos 
comando será necessário para executar como root e ter a permissão necessária para executá-los.

Remoção do módulo:
    Ao final da execução para remover o módulo do sistema, execute o comando sudo rmmod packet_logger.ko.

Bibliotecas não padrões:
    <linux/init.h>: uso de macros como _init e _exit.
    
    <linux/module.h>: definição de constantes MODULE_* e das macros module_init() e module_exit().

    <linux/kernel.h>: contém tipos, macros e funções para o kernel, como a macro pr_info.

    <linux/netfilter.h>: definição das struct nf_hook_ops, sk_buff, nf_hook_state.

    <linux/netfilter_ipv4.h>: define o tipo NF_IP_PRI_FIRST.

    <linux/ip.h>: implementação do protocolo TCP/IP para o sistema operacional LINUX, contém definições para o protocolo IP, como a struct iphdr. 

    <linux/tcp.h>:  implementação do protocolo TCP/IP para o sistema operacional LINUX, contém definições para o protocolo TCP. 

    <linux/udp.h>:  implementação do protocolo TCP/IP para o sistema operacional LINUX, contém definições para o protocolo UDP.
