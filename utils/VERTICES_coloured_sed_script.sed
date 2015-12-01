s/^\([0-9]*\),\("[^"]*"\),"\([^"]*\)",[^,]*,\([0-9]*\)$/\t\1 \[label=\2,shape=\3,fillcolor=\4\];/
s/\bOR\b/diamond/
s/\bAND\b/ellipse/
s/\bLEAF\b/box/