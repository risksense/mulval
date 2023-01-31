# MulVAL
### Multi host, multi stage Vulnerability Analysis tool

To run MulVAL, you need to install the XSB logic engine from http://xsb.sourceforge.net/
You will also need to check whether GraphViz is already installed on your system by typing
"dot". If GraphViz is not installed, you need to install it at http://www.graphviz.org/
Make sure both the program "xsb" and "dot" reside in your PATH.
### Prequirements    
- xsb
- java  
- make and compiler (gcc, g++, etc.)  
- bison and lex      
- graphviz   
- epstopdf:

XSB Can be installed by using the following steps:   
```
wget "https://nav.dl.sourceforge.net/project/xsb/xsb/5.0%20%28Green%20Tea%29/XSB-5.0.tar.gz" -O /usr/local/bin/XSB-5.0.tar.gz
cd /usr/local/bin/
tar -zxvf XSB-5.0.tar.gz   
cd XSB-5.0/build
./configure
./makexsb
```   

The other dependencies can be installed by using distro package management systems. For example, in Ubuntu:  
```     
apt install -y build-essential default-jdk flex bison graphviz texlive-font-utils

```   


#### Setup
The environmental variable MULVALROOT should point to this package's root folder.          

1. Put the environment variable in the current shell or in the .bashrc
```    
export MULVALROOT=<mulval_root>   
export PATH=$PATH:"$MULVALROOT/bin":"$MULVALROOT/utils":<xsb_path>
source ~/.bashrc
```       

2. Type `make` to compile everything    

3. Include $MULVALROOT/bin and $MULVALROOT/utils in PATH. 

You can either run the MulVAL attack-graph generator directly, if you already have an
input file; or you can run the appropriate adapters to create the input files and then 
run the attack-graph generator.

#### Running MulVAL directly

`graph_gen.sh INPUT_FILE [OPTIONS] `

There is a simple input file in testcases/3host/input.P. This input is for the 3-host example in the MulVAL publications [1,2]. You can run it to check whether the attack-graph generator is working correctly:

`graph_gen.sh input.P -v -p`

This will generate an attack graph that matches the description in the papers. Please note that the `-p` option SHOULD NOT BE INVOKED for production use, since it will exponentially slow down the attack-graph generation process, and all it does is to make the attack graph visually palatable (try the above command without the -p option).

By default MulVAL outputs the attack graph in textual format (AttackGraph.txt) and xml format (AttackGraph.xml). The meaning of these formats are self-explanatory. When the `-v` option is invoked, a visual representation of the attack graph will be produced in AttackGraph.pdf through GraphViz. If you have the environment variable PDF_READER set up, the program will be used to open the pdf file automatically.

When the appropriate options are specified (see below), MulVAL also outputs the attack-graph information in CSV format: VERTICES.CSV and ARCS.CSV. The CSV files can be used by a render program to produce various views of the attack graph later (see below).

MulVAL will also output a number of other temporary files in the folder where the program
is run. So it is a good idea to run it in a separate folder to avoid cluttering.

#### OPTIONS

 - Graph generation options:

  `-l`:  output the attack-graph in .CSV format

  `-v`:  output the attack-graph in .CSV and .PDF format

  `-p`:  perform deep trimming on the attack graph to improve visualization **(Do NOT invoke in production)**

 - Reasoning options:

  `-r | --rulefile RULE_FILE`: use RULE_FILE as the interaction ruleset

  `-a | --additional ADDITIONAL_RULE_FILE`: use ADDITIONAL_RULE_FILE in addition to the specified interaction ruleset

  `-g | --goal ATTACK_GOAL`: Specify a single attack goal

  `--cvss`:     use the CVSS information contained in the input file

  `-ma`: use the CVSS information contained in the input file, and perform grouping on the input file. When this option is used, the input file must contain the grouping information (see section II below)

 - RENDERING OPTIONS:

  `--arclabel`: output lables for the arcs

  `--reverse`:  output the arcs in the reverse order

  `--nometric`: do not show the metric information

  `--simple`: do not show the vertex fact labels. *Use this option when attack graph becomes too big to visualize.*

  `--nopdf`: do not generate pdf. *Use this option when you want the DOT file but not the PDF.*

After you have run the `graph_gen.sh` script, you can also invoke the `render.sh` to use the
different rendering options. Simply issue the `render.sh` command in the same directory, 
`render.sh [RENDERING OPTIONS]`



#### Preparing MulVAL input file using adapters

This package contains a number of adapter programs to aid in creating MulVAL input files
from an enterprise network. A number of steps need to be taken as outlined below.

1. Set up an empty MySQL database for storing NVD data, and put the database connection information
into config.txt in a directory where you want to run the MulVAL adapters.
Example config.txt:
```
jdbc:mysql://www.abc.edu:3306/nvd
user_name
password   
```  

Then you can populate the NVD database by typing "nvd_sync.sh". This needs to be done as often
as desired to keep the local MySQL database in sync with NVD. 

2. Translating OVAL/Nessus report into Datalog format.
  * For OVAL: `oval_translate.sh XML_REPORT_FROM_IN_OVAL`
    * The first parameter is the xml file of OVAL scanning result. The output will be in oval.P, summ_oval.P, and grps_oval.P.
    * oval.P is raw input to MulVAL.
    * summ_oval.P is a summarized input after performing grouping as outlined in [3]. This input file is to be used with the `-ma` option. (grps_oval.P contains mapping from vuln groups to raw vuln's)

  * For NESSUS: `nessus_translate.sh XML_NESSUS_REPORT [FIREWALL_RULES]`
    * The first parameter is the XML file of NESSUS scanning result.
    * Optional second parameter is a file containing firewall rules in datalog format. For example `hacl('10.1.2.3', '172.28.2.5', udp, _).` One hacl is defined per line. All rules from this file will be written to `nessus.P` file. If this parameter is missing, then a default rule `hacl(_, _, _, _).` will be written.
    * The output will be in nessus.P, summ_nessus.P, and grps_nessus.P
    * nessus.P is the raw input to MulVAL
    * summ_nessus.P is a summarized input after performing grouping as outlined in [3]. This input file is to be used with the `-ma` option. (grps_nessus.P contains mapping from vuln groups to raw vuln's)

3. Creating hacl tuples

  We assume all machines within the same scanning report can be reached by each other freely. The connection information can be customized as hacl(Host1, Host2, Protocol, Port) in the MulVAL 
input file. All the translated input files will then need to be combined into a single input file.

4. Creating MulVAL attack graph

  Once the input file is created, please refer to the instruction in section I to generate attack graph.

#### Advanced Usage

1. Creating customized rule set.

  To develop your own interaction rules, you can create new rule files, e.g. "my_interaction_rules.P", and use the `-r` or `-a` options to load your rule files. The default rule files can be found under 
the kb/ folder in this package.

  At the beginning of a rule file, you must declare the primitive and derived predicates, and table all derived predicates. Facts with primitive predicates come from the input, and facts with derived predicates are defined by the interaction rules. Every predicate used by the interaction rules must have a declaration of either "primitive" or "derived", otherwise you may get an error message of "undefined predicate" during evaluation, and the attack graph generation may fail with a warning message telling you which predicate's declaration is missing. Tabling will prevent the XSB reasoning engine from entering an infinite loop and increase the efficiency of reasoning by memoizing intermediate
results.

  Each interaction rule is introduced by "interaction_rule(Rule, Label)", where Rule is a Datalog rule and Label is some plain-text explaining its meaning. The labels will become annotations in attack graph. 
Once you have developed your own rule set, you can test it by using the `-r RULEFILE` option with `graph_gen.sh` to let it load RULEFILE instead of using the default ruleset. If you want your rule file to be added to the default ruleset, you can use the `-a RULEFILE` option instead.

2. Calculating risk metrics based on CVSS and MulVAL attack graph

  We have included a quantitative risk assessment algorithm based on Wang et al. [4]. It combines the CVSS metrics and the attack graph to compute a probabilistic risk metrics for the enterprise
network. To run the metric program, type in the following command where the attack-graph output is located:
`probAssess.sh`

  There is also a script that integrates multiple steps: creating MulVAL attack graph, running the risk metrics algorithm and display the attack graph with metrics:
`riskAssess.sh INPUT [OPTIONS]`

  It will run MulVAL on the input file. This script will always use the -ma (modeling artifact) 
option to generate attack graph. Please use summ_oval.P (generated by oval_translate.sh) or summ_nessus.P (generated by nessus_translate.sh) as the INPUT. Use OPTIONS to pass any additional 
options to the MulVAL attack-graph generator (graph_gen.sh)

#### REFERENCES:  
``` 
[1] Xinming Ou, Wayne F. Boyer, and Miles A.McQueen. A scalable approach to attack graph generation. In 13th ACM Conference on Computer and Communications Security (CCS), 2006.

[2] Xinming Ou, Sudhakar Govindavajhala, and Andrew W. Appel. MulVAL: A logic-based network security analyzer. In 14th USENIX Security Symposium, 2005.

[3] Su Zhang, Xinming Ou, and John Homer. Effective network vulnerability assessment through model abstraction. In Eighth Conference on Detection of Intrusions and Malware & Vulnerability Assessment
(DIMVA), Amsterdam, The Netherlands, 2011.

[4] Lingyu Wang, Tania Islam, Tao Long, Anoop Singhal, and Sushil Jajodia. An attack graph-based probabilistic security metric. In Proceedings of The 22nd Annual IFIP WG 11.3 Working Conference
on Data and Applications Security (DBSEC’08), 2008.


```