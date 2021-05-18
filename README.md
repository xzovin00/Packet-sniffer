# IPK projekt 2 - Packet sniffer
**Autor:** Martin Žovinec
### Popis:
Síťový analyzátor, který naurčitém síťovém rozhraní zachytává a filtruje pakety. Projekt je implementován v jazyce C.

## Příklad spuštění
./ipk-sniffer [-i _rozhraní_] {-p ­­_port_} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n _num_}

#### Argumenty:
- {-r rozhraní } rozhraní, na kterém se má poslouchat (bez uvedení parametru vypíše všechny aktivní rozhraní a program ukončí)
- [=p port] port, na kterém se bude poslouchat (bez uvedení se uvažují všechny porty)
- [-n  num] určuje počet paketů, které se mají zobrazit (bez uvedení se zobrazí pouze jeden paket)
- [-t | --tcp] spustí filtrování tcp paketů
- [-u | --udp] spustí filtrování udp paketů
- [--icmp] spustí filtrování icmp paketů
- [--arp] spustí filtrování arp paketů
- (bez zvolení argumentu pro filtrování se budou filtrovat všechny uvedené)

### Další příklady spuštění
./ipk-sniffer -i eth0 -p 23 --tcp -n 2  
./ipk-sniffer -i eth0 --udp  
./ipk-sniffer -i eth0 -n 10  
./ipk-sniffer -i eth0 -p 22 --tcp --udp --icmp --arp .... stejné jako:  
./ipk-sniffer -i eth0 -p 22  
./ipk-sniffer -i eth0

## Odevzdané soubory
ipk-sniffer.c
Makefile
README
manual.pdf
