%{
    #ifndef LINUX
     #include <Windows.h>
    #endif
    #include <stdio.h>
    #include <string.h>
    #include "attack_graph.h"
    #define YYSTYPE char *
    //#define YY_NEVER_INTERACTIVE
    //#define YYDEBUG 1
    //#define DEBUG 1
    extern YYSTYPE yylval;
    extern "C"
    {
        int yyparse(void);
        int yylex(void);
        YYSTYPE* mylval = &yylval;
       int yywrap()
       {
           return 1;
       }
    }

    extern graph_data data;

    #define MAXLEN 1000
    #define CVSSAC_PREFIX "cvss_ac_"
    #define CAP_LUCK_PREFIX "cap_"
    char trace_step_key[MAXLEN+1]; 
    char fact1_str[MAXLEN+1]="";
    char fact_str[MAXLEN+1]="";
    char facts_str[MAXLEN+1]="";
    char desc_str[MAXLEN+1]="";
    char name_str[MAXLEN+1]="";
    char metric_str[MAXLEN+1] = "";
    char arglist_str[MAXLEN+1]="";
    char str[MAXLEN+1]= "";
    char *special_char_str;
    char *fact_ptr;
    char *fact1_p = (char *)fact1_str;
    char *fact_p = (char *)fact_str;
    //    char *desc_p = (char *)desc_str;
    char *facts_p = (char *)facts_str;
    char *arglist_p = (char *)arglist_str;
    char *str_p = (char *)str;

    Fact *lastFact=0;
    Fact *fact1=0;
    Queue<Fact> factQ;
    int arg_count=0;

  void yyerror(char *s) {
    fprintf(stderr, "%s\n", s);
  }

%}

%token ATTACK_TOKEN TRACESTEP_TOKEN BECAUSE_TOKEN ATOM QUOTE SP '.' END_LINE
       PRIMITIVE DERIVED META METRIC DESC FLOAT CVSS_AC CAP_LUCK

%%
lines: 
            | lines line
            ;

line: blank_line
    | trace_step
    | attack_fact
    | predicate_type
    | fact_metric
    ;

blank_line: END_LINE
          | SP END_LINE 
          ;

predicate_type: PRIMITIVE '(' ATOM ',' ATOM ')' '.' END_LINE
                     {
                        data.all_predicates.add_predicate( $3, atoi($5), 
                                      primitive);
                     }
              | DERIVED   '(' ATOM ',' ATOM ')' '.' END_LINE
                     {
                        data.all_predicates.add_predicate( $3, atoi($5), 
                                     derived);
                     }

              | META   '(' ATOM ',' ATOM ')' '.' END_LINE
                     {
                        data.all_predicates.add_predicate( $3, atoi($5), 
                                     meta);
                     }


fact_metric: METRIC '(' fact ',' metric ')' '.' END_LINE
                     {
		       lastFact->metric = atof(metric_str);

		       fact1_str[0] = 0;
		       lastFact=0;
		       fact1=0;

		       // make sure the fact Q is empty
		       // factQ.emptyQ();

                     }

trace_step:
    TRACESTEP_TOKEN '(' BECAUSE_TOKEN '(' ATOM ',' DESC '(' QUOTE desc QUOTE ',' metric ')' ',' fact ',' conjunct ')' ')' '.' END_LINE
        {
           int rulenum = atoi($5);

          if ( (strlen(desc_str) + strlen(fact1_str)  +
		strlen(facts_str) + strlen(metric_str) + strlen($5) + 9) > MAXLEN  ) {
              cerr << "ERROR: tracestep overflow\n";
              exit(1);
           }
           //rebuild the parsed tracestep for the key
           #ifdef LINUX
           snprintf(trace_step_key,MAXLEN,"%s,%s,'%s',%s,[%s]",
		    $5,metric_str,desc_str,fact1_str,facts_str  );
           #else
           sprintf(trace_step_key,"%s,%s,'%s',%s,[%s]",
		   $5,metric_str,desc_str,fact1_str,facts_str  );
           #endif

           // save unique trace step
           data.all_trace_steps.add_step( trace_step_key,
	   			  rulenum, metric_str, fact1, factQ);

           // save unique rule
           data.ruleList.add_rule(rulenum, desc_str);

           #ifdef DEBUG 
           printf("possible_duplicate_trace_step(because(%s)).\n\n",
                                trace_step_key);
           #endif
             // empty the strings used for building trace step
             fact1_str[0] = 0;
             fact_str[0] = 0;
             facts_str[0] = 0;
             lastFact=0;

             // empty the fact queue without deleting facts
             factQ.emptyQ();
        }

       ;

metric:
       ATOM  
       { 
	 if (strlen($1) > MAXLEN){
	   cerr << "ERROR: metric string overflow\n";
	   exit(1);
	 }
	 strcpy(metric_str, $1);
       }
      |FLOAT 
       {
	 if (strlen($1) > MAXLEN){
	   cerr << "ERROR: metric string overflow\n";
	   exit(1);
	 }
	 strcpy(metric_str, $1);
       }
/*
      |QUOTE desc QUOTE
       {
	 strcpy(metric_str, desc_str);
       }
*/
      |cvss_metric
      |cap_metric
      ;

cvss_metric:  CVSS_AC '(' ATOM ')' 
              { 
		if (strlen(CVSSAC_PREFIX)+strlen($3) > MAXLEN){
		  cerr << "ERROR: metric string overflow\n";
		  exit(1);
		}
		strcpy(metric_str, CVSSAC_PREFIX);
		strcat(metric_str, $3);
	      }
              ;

cap_metric:  CAP_LUCK '(' ATOM ')' 
              { 
		if (strlen(CAP_LUCK_PREFIX)+strlen($3) > MAXLEN){
		  cerr << "ERROR: metric string overflow\n";
		  exit(1);
		}
		strcpy(metric_str, CAP_LUCK_PREFIX);
		strcat(metric_str, $3);
	      }
              ;

attack_fact:
        ATTACK_TOKEN '(' fact ')'  '.' END_LINE
        {
                #ifdef DEBUG 
                printf("attack(%s).\n\n",fact1_str);
                #endif
		data.goals[fact1_str] = NULL;
                fact1_str[0] = 0;
                lastFact=0;
		fact1=0;

             // make sure the fact Q is empty
             // factQ.emptyQ();
        }
        ;

special_char:
      SP  {special_char_str=" ";}
    | '(' {special_char_str="(";}
    | ')' {special_char_str=")";}
    | '[' {special_char_str="[";}
    | ']' {special_char_str="]";}
    ;

quoted_name: 
      ATOM
             { 
	       strncpy(name_str, $1, MAXLEN);
	     }
    | quoted_name ATOM
             {
	       strncat(name_str,$2,MAXLEN-strlen(name_str));
	     }
    | quoted_name special_char
             {
	       strncat(name_str,special_char_str,MAXLEN-strlen(name_str));
	     }
    ;

desc: 
    | ATOM
             { 
	       strncpy(desc_str, $1, MAXLEN);
	     }
    | desc SP ATOM   
             { 
	       strncat(desc_str," ",MAXLEN-strlen(desc_str));
	       strncat(desc_str,$3,MAXLEN-strlen(desc_str));
	     }
    ;

arglist: factString
              {
                  strncat(arglist_p,str,MAXLEN);
                  arg_count =1;
               }
    | arglist ',' factString 
              { 
                     strncat(arglist_p,",",MAXLEN);
                     strncat(arglist_p,str,MAXLEN);
                     arg_count++ ;
               }
    ;

factString: ATOM {strcpy(str,$1); if (str[0] == '_') strcpy(str, "_");}
          | QUOTE quoted_name QUOTE  {strcpy(str,"'"); strcat(str,name_str); strcat(str,"'");}
          ;

/*
          | factString ATOM   {strcpy(str,$2); }
          | factString QUOTE ATOM QUOTE  {strcat(str,"'"); strcat(str,$2); strcat(str,"'"); }
*/

facts:  
        | fact
              {
                   strncat(facts_p,fact_p,MAXLEN);
                   if( lastFact != NULL) { 
                     factQ.add(*lastFact);
		     //exit (-1);
                   }
                    // empty the fact used for building fact list
                    fact_str[0] = 0;
               }
        | facts ',' fact 
              { 
                   strncat(facts_p,",",MAXLEN);
                   strncat(facts_p,fact_p,MAXLEN);
                   if( lastFact != NULL) { 
                     factQ.add(*lastFact);
                   }
                    fact_str[0] = 0;
               }
        ;

fact:  ATOM '(' arglist ')' 
              { 
                   bool first_fact;
                   if( strlen(fact1_str) ==  0 ) {
                       first_fact = true;
                       fact_ptr = fact1_p;
                   } else {
                       first_fact = false;
                       fact_ptr = fact_p;
                   }
                    strncat(fact_ptr,$1,MAXLEN);
                    strncat(fact_ptr,"(",MAXLEN);
                    strncat(fact_ptr,arglist_p,MAXLEN);
                    strncat(fact_ptr,")",MAXLEN);

                    // get the pointer to correct predicate 
                    Predicate *p = 
                     data.all_predicates.add_predicate( $1, arg_count, undef);

                    // add this fact to the fact list, unless 
                    // it is already in the list. 
                    lastFact=data.all_facts.add_fact( fact_ptr,p, arglist_p);
                    if( first_fact) fact1 = lastFact;

                    // empty the list for building next fact string
                    arglist_str[0] = 0;
                    arg_count=0;
               }
      ;

conjunct: '[' facts ']'  
        ;



