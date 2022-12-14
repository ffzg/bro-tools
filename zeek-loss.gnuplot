# zgrep sw-dpc-2 logs/2022-12-13/capture_loss.* | sed 's/.gz:/.gz\t/' | tee ~dpavlin/2022-12-14-zeek-capture_loss.log

# cpu pinning is very important if you want to make use of caches.

set term png
set output "zeek-loss.png"

set title "zeek etc/node.cfg pin\\\_cpus=1 effect on tg3 10g sfp capture\\\_loss.log" 

set datafile separator "\t"
set timefmt "%s"
set xdata time
set ylabel "% capture loss"
plot '2022-12-14-zeek-capture_loss.log' using 2:7 with linespoints
