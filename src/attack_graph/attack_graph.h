/*
Generates MulVAL attack-graph based on MulVAL reasoning trace and a policy file.
Author(s): Wayne Boyer, Xinming Ou
Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _ATTACK_GRAPH
#define _ATTACK_GRAPH

//#define USE_HASH

#include "Queue.h"
#include <map>
#include <string.h>
#include <stdlib.h>

#ifdef USE_HASH
 #ifdef LINUX
#include <hash_map.h>
using __gnu_cxx::hash_map;
 #else
#undef _DEFINE_DEPRECATED_HASH_CLASSES
#define _DEFINE_DEPRECATED_HASH_CLASSES 0
#include <hash_map>
using namespace stdext;
 #endif
#endif

using namespace std;
// may need for windows
//using namespace stdext;

#define MAX_RULES 1000
class Node;

enum Type {primitive, derived, meta, undef};
enum NodeType{OR, AND, LEAF};
enum renderMode{ TEXT, HTML}; 
enum arcLabelMode{WEIGHT, NUMBER, METRICMODE, NONE}; 
enum removeStatus{ REMOVE, SUCCESS };
enum pruneOption{noPrune, unFounded, nonSimple};
enum dfsAlgorithm{reAssignNodeNum, none};
const string indentStep = "   ";

// functions and declarations for metric manipulation
bool betterMetric(float betterMetric, float metric);
float metricCombine(float subMetric, float singleMetric);
#define IDENTITY_METRIC 1




class Term{
      public:
      //int hashCode;
      //char* key;
};

//class Predicate : public Term{
class Predicate {
      public:
  Predicate(string &s, Type t, int a) { predicate= s; type=t; arity=a;} 

  Type type;
  int arity;
  string predicate;
};

/*
//class Rule : public Term{
class Rule  {
      public:
  int ruleNum;
  char ruleDescription[]; // string
};
*/

class Rules{
     public:
     Rules() { for (int i=0;i<MAX_RULES;i++) rules[i] =0; count=0; }
     ~Rules() {for (int i=0; i<MAX_RULES; i++)  free(rules[i]); }

     int count ; 
     char* rules[MAX_RULES] ;
     // float metrics[MAX_RULES];
     // char* metric_strings[MAX_RULES];

     //     void add_rule( int rulenum, char* desc, float metric);
     void add_rule( int rulenum, char* desc);
};

//class Fact : public Term{
class Fact {
      public:
      Fact(string k,Predicate *p, string a) 
                     { arguments= a; key =k; predicate =p; metric=-1;}

      string key;
      Predicate *predicate;
      string arguments;
      float metric;

      // methods
      void Render(renderMode mode, int indent );
      void Render(renderMode mode, int indent, int nodenum);
      void Render(renderMode mode, int indent, int nodenum, int size);
};

//class Conjunct : public Term{
class Conjunct {
      public:
      ~Conjunct(){ factList.emptyQ(); } // don't free fact memory

      Queue<Fact> factList;   // a list of facts
};

//class TraceStep : public Term{
class TraceStep {
      public:
  TraceStep(int r, char *m, Fact *f, Conjunct *c);/* { 
    ruleNum=r;

    if (useRuleMetrics){
      metrics = atof(m);
    }
    else{
      metrics = data.metrics[m];
    }

    fact = f; 
    conjunct=c; 
    }*/
  
  int traceNum;
  int ruleNum;
  float metric;
  Fact *fact;
  Conjunct *conjunct;  
};

class Node{
 public:
  int nodeNum;

  // methods
  /* Each time an dfsAlgorithm is called, the 
     currentCounter global variable must be
     incremented by one */
  virtual  void dfs(dfsAlgorithm alg) = 0;

  virtual bool WellFounded(int level) = 0;

  virtual void RemoveUnfoundedEdges() = 0;

  // returns the length of the shortest attack
  // path that leads to this node
  virtual int allSimplePaths() = 0;
  virtual float bestMetric() = 0;

  virtual void pruneUselessEdges() = 0;

  virtual int CountAndNodes();
  // virtual int ReAssignNodeNum(int nodeNum) = 0;
  virtual void Render(renderMode  mode, int indent) = 0; 
  // return true if rendered, false otherwise
  virtual bool Render2(arcLabelMode mode) = 0;
  virtual void outputVertex(string description, float metric) = 0;
  virtual int  TransformToCNF(int parent) = 0;
};


class Arc{
  Node *src;
  Node *dst;

 public:
  int arcNum;
  // the length of the shortest attack path leading to the src
  int weight;
  // the metric computed from the simple attack paths following the arc
  float metric;

  Arc(Node *s, Node *d){
    src = s;
    dst = d;
    weight = -1;
    metric = -1;
  }

  Node* getSrc(){
    return src;
  }

  Node* getDst(){
    return dst;
  }
  
  void Render(arcLabelMode mode);
};
  
class OrNode : public Node{
  Fact *label;
  int visited;
  bool inPath;
  int dfsCounter;
  bool dfsInPath;
  bool wellFounded;
  enum pruneStatus {Unfounded, Useless, None};
  pruneStatus pruned;
  bool rendered;
  int cnfNum;
  float nodeMetric;

 public:
  Queue<Arc> outGoing;

  OrNode(Fact *f) {
    label = f;
    visited = 0;
    inPath = false;
    dfsCounter = 0;
    dfsInPath = false;
    wellFounded = false;
    pruned = None;
    rendered = false;
    cnfNum = 0;
    nodeMetric = -1;
  }
  
  ~OrNode(){ 
    outGoing.emptyQ(); 
    // should also free the memory of the arc objects
  }

  bool WellFounded(int level);
  void RemoveUnfoundedEdges();
  int allSimplePaths();
  float bestMetric();
  void pruneUselessEdges();
  int CountAndNodes();
  void dfs(dfsAlgorithm alg);
  int ReAssignNodeNum(int nodeNum);
  void Render(renderMode  mode, int indent); 
  bool Render2(arcLabelMode mode);
  void outputVertex(string description, float metric);
  int TransformToCNF(int parent);
};


class AndNode : public Node{
  int rulenum ;
  float metric ;
  // An AndNode has only one parent

 public:
  int parentNodeNum;
  Queue<Arc> outGoing;

  AndNode(int rule, float m){ 
    rulenum = rule; 
    metric = m;
  }
  ~AndNode(){ 
    outGoing.emptyQ(); 
    // should also free the memory for the arcs
  }

  float getMetric() {return metric;}

  bool WellFounded(int level);
  void RemoveUnfoundedEdges();
  int allSimplePaths();
  float bestMetric();
  void pruneUselessEdges();
  int CountAndNodes();
  void dfs(dfsAlgorithm alg);
  void Render(renderMode  mode, int indent); 
  bool Render2(arcLabelMode mode);
  void outputVertex(string description, float metric);
  int TransformToCNF(int parent);
};

class LeafNode : public Node{
  Fact *label ;
  bool rendered, visited;
  int cnfNum;
  int dfsCounter;

 public:
  LeafNode(Fact *f) {
    label = f; 
    rendered = false;
    dfsCounter = 0;
    cnfNum = 0;
  }
  
  bool WellFounded(int level);
  void RemoveUnfoundedEdges();
  int allSimplePaths();
  float bestMetric();
  void pruneUselessEdges();
  void dfs(dfsAlgorithm alg);
  void Render(renderMode  mode, int indent); 
  bool Render2(arcLabelMode mode);
  void outputVertex(string description, float metric);
  int TransformToCNF(int parent);
};


// The following class defines a hash function for strings 
#ifdef USE_HASH
#ifdef LINUX
class stringhasher
#else
class stringhasher : public stdext::hash_compare <std::string>
#endif
{
public:
  /**
   * Required by 
   * Inspired by the java.lang.String.hashCode() algorithm 
   * (it's easy to understand, and somewhat processor cache-friendly)
   * @param The string to be hashed
   * @return The hash value of s
   */
  size_t operator() (const string& s) const
  {
    size_t h = 0;
    std::string::const_iterator p, p_end;
    for(p = s.begin(), p_end = s.end(); p != p_end; ++p)
    {
      h = 31 * h + (*p);
    }
    return h;
  }

/**
   * 
   * @param s1 The first string
   * @param s2 The second string
   * @return true if the first string comes before the second in lexicographical order
   */
  bool operator() (const std::string& s1, const std::string& s2) const
  {
    return s1 < s2;
  }
};


typedef hash_map <string,Predicate *,stringhasher> predicateMap;
typedef hash_map<string,Fact *,stringhasher> factMap;
typedef hash_map<string,TraceStep *,stringhasher> traceStepMap;
typedef hash_map<string,Node *,stringhasher> NodeMap;
typedef hash_map<string, float, stringhasher> MetricMap;
#else
typedef map<string,Predicate *> predicateMap;
typedef map<string ,Fact *> factMap;
typedef map<string,TraceStep *> traceStepMap;
typedef map<string,Node *> NodeMap;
typedef map<string, float> MetricMap;
#endif

class factContainer{
    public:
  /* This might have caused double-free error.
    ~factContainer() { factMap::iterator i;
                       for(i=facts.begin(); i != facts.end(); ++i) {
                            delete i->second;
                       } 
                     } // free up the fact memory
  */
    factMap facts;

    Fact* add_fact( char * key, Predicate *predicate, char* args);
};

class nodeContainer{
    public:
  /* This might have caused double-free error.
    ~nodeContainer() { NodeMap::iterator i;
                       for(i=nodes.begin(); i != nodes.end(); ++i) {
                            delete i->second;
                       } } // free up the node memory
  */
    NodeMap nodes;

    OrNode* addOrNode(string &key, Fact *label); 
    LeafNode* addLeafNode(string &key, Fact *label); 
};

class predicateContainer{
    public:
  /* This might have caused double-free error.
    ~predicateContainer() { predicateMap::iterator i;
                       for(i=predicates.begin(); i != predicates.end(); ++i) {
                            delete i->second;
                       } 
                     } // free up the predicate memory
  */
    predicateMap predicates;

    Predicate* add_predicate( char* predicate, int arity, Type type);
};

class traceStepContainer{
    public:
    traceStepContainer() {count=0;}
    /* This might have caused double-free error.
    ~traceStepContainer() { traceStepMap::iterator i;
                       for(i=traceSteps.begin(); i != traceSteps.end(); ++i) {
                            delete i->second;
                       } 
                     } // free up the node memory
    */
    traceStepMap traceSteps;
    int count;

    TraceStep* add_step(char* key, int rulenum, char *metric, Fact *f, Queue<Fact> &fl );
};

class nodeQ {
     public:
     // We need this class for a simple node container because
     //  nodes have Queues. The destructor cleanly frees the node
     //  memory without affecting the sub Queus.
     ~nodeQ() {
               /* for(Node *n = nodeList.gethead(); n>0;
                                             n = nodeList.getnext() ) {
                     n->children.emptyQ();
                     delete n ;
               }
               */
               nodeList.dump();
              
      }

     Queue<Node> nodeList; 
};

struct metric_map{
  string metricString;
  float metric;
};

class graph_data{
     public:
         graph_data(metric_map mp[], int size){
	   for (int i=0; i<size; i++){
	     metrics[mp[i].metricString] = mp[i].metric;
	   }
	 }
     NodeMap goals;
     static int visitedCounter;
     static int nodeCount;
     static int orNodeCount;
     static int leafNodeCount;
     Rules ruleList; 
     factContainer all_facts;
     predicateContainer all_predicates;
     traceStepContainer all_trace_steps;
     nodeContainer      all_or_nodes;
     nodeContainer      all_leaf_nodes;
     nodeQ              all_and_nodes;
     MetricMap          metrics;
};

/* Also need implementation of the object tables.
   The look up efficiency of the table is crucial
   in the performance */

#endif
