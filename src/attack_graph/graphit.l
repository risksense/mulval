%{
#include <stdio.h>
#include "y.tab.cpp.h"
#define YYSTYPE char * 
YYSTYPE* mylval;
FILE **my_ptr = &yyin; 
%}


%%
^attack                          return ATTACK_TOKEN;
^possible_duplicate_trace_step   return TRACESTEP_TOKEN;
because                        return BECAUSE_TOKEN;
rule_desc                   return DESC;
^primitive                     return PRIMITIVE;
^derived                       return DERIVED;
^meta                       return META;
^metric                      return METRIC;
cvss_ac                      return CVSS_AC;
cap_luck                      return CAP_LUCK;
\'                           return QUOTE;
\n                           return END_LINE;
[0-9]*\.[0-9]+                *mylval=(char *)strdup(yytext); return FLOAT;
[\.\[\]\,\(\)]                 return (int) yytext[0];
[\/a-zA-Z0-9_\-\+\.]+     *mylval=(char *)strdup(yytext); return ATOM;
[ \t]+                       return SP;
%%


