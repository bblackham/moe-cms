cat <<EOF

Uzitecne prikazy:
'rhide' - spusti vyvojove prostredi pro C/C++
'mc' - spusti program pro praci se soubory (podobny Norton Commanderu)
'compile <uloha>' - zkompiluje ulohu <uloha> se stejnymi parametry kompilatoru,
  s jakymi bude vas program kompilovan pri testovani
'check <uloha>' - spusti vase reseni ulohy <uloha> na vzorovy vstup a vypise, zda vas program
  dal spravny vystup
'submit <uloha>' - odesle zdrojovy text programu pro ulohu <uloha> k vyhodnoceni

EOF
export MO_PUBLIC=/aux/mo/public
PATH=$PATH:$MO_PUBLIC/bin
