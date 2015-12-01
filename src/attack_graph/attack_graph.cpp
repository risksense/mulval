// TODO: currently the unFounded mode pruning is broken. Need fixing.
/*
Generates MulVAL attack-graph based on MulVAL reasoning trace and a policy file.
Author(s) : Wayne Boyer, Xinming Ou
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

#ifndef LINUX
#include <Windows.h>
#endif
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include "attack_graph.h"
#include <vector>
#include <cstdlib>

extern FILE* yyin;
extern "C"
{
    int yyparse(void);
    #ifndef LINUX
    extern FILE **my_ptr;
    #endif
}

// local prototypes
int build_graph(void);
int build_visual(bool);
int build_cnf(void);
void dump_tables(void);
void draw_a_link( renderMode mode, int indent, int nodeNumber, Fact *label);
void RenderRule( renderMode mode, int indent, int rulenum );
void RenderRule( renderMode mode, int indent, int rulenum, int nodeNum);
void process_args(int argc, char *argv[]);
void print_usage();


/*****************************/
/*      Global variables     */
/*****************************/

char* tracefile_name = NULL;

/* if true, the nodes and arcs will be output as
   separate lists */
bool arc_and_node = false;
bool noSink = false;
arcLabelMode arc_mode = METRICMODE;

/* prune option determines the pruning method */
pruneOption prune_option = noPrune;

/* global data used in the various dfs algorithms*/
int currentCounter = 0;
/* used in reAssignNodeNum */
int currentNodeNum = 1;
int currentArcNum = 1;


bool test=false;
bool buildCNF=false;
bool useMetrics=false;
bool useRuleMetrics=false;
bool displayMetric=true;

metric_map mp[] = {
  {"certain", 1},
  {"likely",  .8},
  {"possible", .5},
  {"unlikely", .2},
  {"cvss_ac_h", .2},
  {"cvss_ac_m", .6},
  {"cvss_ac_l", .9},
  {"cap_h", .1},
  {"cap_m", .2},
  {"cap_l", .4},
};

int size_mp = 10;

graph_data data(mp, size_mp); 

// initialize static members
//Fact *graph_data::goal =0;
int  graph_data::visitedCounter =0;
int  graph_data::nodeCount =0;
int  graph_data::orNodeCount =0;
int  graph_data::leafNodeCount =0;

// Global counters : number of variables and number of clauses
int cnfCounter = 0;
int clauseCounter = 0;
int primitiveCounter = 0;
int derivedCounter = 0;
// Global vector for mapping cfnNum to node, default size 25
vector <string> mapCNF (20);
vector <string> mapClauses (25);
vector <string> mapPrimitives (25);
vector <string> mapDerived (25);
// File handles
ofstream fileCNF;
ofstream fileMap;
ofstream filePrimitiveFacts;
ofstream fileDerivedFacts;


/***************************************************************/
/* functions for metric operations. Change the following two   */
/*       functions to modify the metric semantics              */
/***************************************************************/

//requires that both metrics are meaningful (>=0)
bool betterMetric(float betterMetric, float metric){
  return betterMetric > metric;
}

//requires that both metrics are meaningful (>=0)
float metricCombine(float subMetric, float singleMetric){
  if (subMetric < 0) return singleMetric;
  if (singleMetric < 0) return subMetric;
  return subMetric * singleMetric;
}



Fact* factContainer::add_fact(char *key, Predicate *p, char* args)
{
  //   static bool first_fact = true;
   Fact *f ;
   factMap::iterator i;

   string key_str = key;
   i= facts.find( key_str );

   if( i  == facts.end() ) {
       f = new Fact(key,p,args) ;
       if( f == NULL) {
              cerr << "Failed to create new fact\n";
              exit(1);
       }
       facts[ key_str ] = f;
       /*
       if(first_fact) {
           first_fact = false;
           graph_data::goal = f;
       }
       */
   }
   else {
       f = i->second;
   }

   return f;
}

TraceStep::TraceStep(int r, char *m, Fact *f, Conjunct *c) { 
  ruleNum=r;
  
  if (useRuleMetrics){
    metric = atof(m);
  }
  else{
    metric = data.metrics[m];
  }
  
  fact = f; 
  conjunct=c; 
}


TraceStep* traceStepContainer::add_step(char* key, int rulenum, char *metric, Fact *f, Queue<Fact> &fl )
{
   TraceStep *ts;
   traceStepMap::iterator i;
   string key_str = key;
   i= traceSteps.find( key_str );

   if( i == traceSteps.end() ) {
        // create a new conjunction, link it to the tracestep
        // It will be linked to a node later.
        Conjunct *cj = new Conjunct();
        if( cj == NULL) {
              cerr << "Failed to create new conjunction\n";
              exit(1);
        }
        fl.copy(cj->factList);
        ts = new TraceStep( rulenum, metric, f, cj);
        if( cj == NULL) {
              cerr << "Failed to create new trace-step\n";
              exit(1);
        }
        count++;
        ts->traceNum = count;
        traceSteps[ key_str ] = ts;
   }
   else { ts = i->second; }
   return ts;
}

/*
void Rules::add_rule( int rulenum, char* desc, float ruleMetric )
{
      if ( rulenum > MAX_RULES) {
            cerr << "add_rules: error, rulenum out of range\n";
            exit(1);
      }
      if ( rules[rulenum] ==0) {
          if( rulenum> count) count = rulenum;
          char *r = (char *)malloc(strlen(desc)+1);
          strcpy(r,desc);
          rules[rulenum] = r;
	  metrics[rulenum] = ruleMetric;
      }
}
*/

void Rules::add_rule( int rulenum, char* desc )
{
      if ( rulenum > MAX_RULES) {
            cerr << "add_rules: error, rulenum out of range\n";
            exit(1);
      }
      if ( rules[rulenum] ==0) {
          if( rulenum> count) count = rulenum;
          char *r = new char[strlen(desc)+1];
          strcpy(r,desc);
          rules[rulenum] = r;
	  /*
	  if (ruleMetricString != NULL){
	    metric_strings[rulenum] = ruleMetricString;
	    if (useRuleMetrics){
	      metrics[rulenum] = atof(ruleMetricString);
	    }
	    else{
	      metrics[rulenum] = data.metrics[ruleMetricString];
	    }
	  }
	  else{
	    metric_strings[rulenum] = "undefined";
	    metrics[rulenum] = -1;
	  }	
	  */    
      }
}

Predicate* predicateContainer::add_predicate(char *s, int a, Type t)
{
   Predicate *p ;
   predicateMap::iterator i;
   char arity[10] ; 
   if ( a > 100000000) {
        cerr << "ERROR: arity overflow\n";
        exit(1);
   }
   #ifdef LINUX
   snprintf(arity,9,  "%d",a); 
   #else
   sprintf(arity,"%d",a); 
   #endif

   string str = s ;
   string pred = s ;
   str = pred + '/' + arity;
   i= predicates.find( str );

   if( i  == predicates.end() ) {
       p = new Predicate(pred,t, a) ;
       if( p == NULL) {
          cerr << "Failed to create new predicate\n";
          exit(1);
       }
       predicates[str] = p;
       if( t == undef ) {
               cerr << "Error: Predicate " << str  
                    << " created with undefined type.\n" ;
               exit(1);
       }
   }
   else {
       p = i->second;
   }

   return p;
}

bool OrNode::WellFounded(int level)
{
  if (inPath) return false;
  if (visited > level) return wellFounded;

  inPath = true;

  wellFounded = false;
  for (Arc *arc = outGoing.gethead() ; arc != NULL ; arc = outGoing.getnext() ) {
    //if any of the children of an OrNode returns true, the
    // whole OrNode should return true
    if (arc->getDst()->WellFounded(level)) {
      wellFounded = true;
      break;
    }
  }
  inPath = false;
  visited = level+1;
  return wellFounded;
}

bool AndNode::WellFounded(int level)
{
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    //if any of the children of an AndNode returns false, the
    // whole AndNode should return false
    if (!arc->getDst()->WellFounded(level)) {
      return false;
    }
  }
  return true;
}

bool LeafNode::WellFounded(int level)
{
  return true;
}

void OrNode::RemoveUnfoundedEdges()
{
  // If we have already processed this node, return
  if (pruned == Unfounded) return;
  pruned = Unfounded;

  // Pretend that this node is unfounded and test if its children can still be
  // well founded
  visited = graph_data::visitedCounter+1;
  wellFounded = false;

  QueueItem<Arc> *arcItemNext = NULL;
  for (QueueItem<Arc> *arcItem = outGoing.getheadQitem(); 
       arcItem != NULL ; 
       arcItem = arcItemNext) {
    arcItemNext = outGoing.getnextQitem(arcItem);
    Arc *arc = outGoing.getitem(arcItem);
    if (!arc->getDst()->WellFounded(graph_data::visitedCounter)) {
      outGoing.remove(arcItem);
    }
  }

  // recursively call the children to prune other edges
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    graph_data::visitedCounter++;
    arc->getDst()->RemoveUnfoundedEdges(); 
  }
}

void AndNode::RemoveUnfoundedEdges()
{
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    arc->getDst()->RemoveUnfoundedEdges();
  }
}

void LeafNode::RemoveUnfoundedEdges()
{}


// return the length of the shortest simple path
// -1 if no simple path
int OrNode::allSimplePaths()
{
  if (inPath){
    return  -1;
  }
  
  // Extend the DFS path
  inPath = true;
  int shortestLength = -1;

  // Recursively call on all the children
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    // if there is a simple path, record the length
    int length = arc->getDst()->allSimplePaths();
    if (length >= 0) {
      if (arc->weight < 0 || length + 1 < arc->weight){
	arc->weight = length + 1;
      }
      if (shortestLength < 0 || length + 1 < shortestLength){
	shortestLength = length + 1;
      }
    }
  }

  inPath = false;
  return shortestLength;
}

// Since all the children of an AndNode are required for the attack 
// to be successful, the shortest attack path corresponds to the ~largest~
// value of all the outgoing arcs' weights
// return -1 if no attack path
// could also consider returning the sum of all the outgoing arcs' weights
int AndNode::allSimplePaths()
{
  int largestWeight = 0;
  // Recursively call on all the children
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()){
    int length = arc->getDst()->allSimplePaths();
    // if one child does not have a simple path, return -1
    if (length < 0){
      return -1;
    }
    if (arc->weight < 0 || length + 1 < arc->weight){
      arc->weight = length + 1;
    }
    if (largestWeight < length + 1){
      largestWeight = length + 1;
    }
  }
  return largestWeight;
}

int LeafNode::allSimplePaths()
{
  return 0;
}

// return the "best" metric of all simple paths starting from the node
float OrNode::bestMetric()
{
  if (inPath){
    return  -1;
  }

  // If the node's metric has already been computed, just return the stored value.
  if (nodeMetric >= 0){
    return nodeMetric;
  }
  
  // Extend the DFS path
  inPath = true;
  float bestMetric = -1;

  // Recursively call on all the children
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    // if there is a metric, record it
    float metric = arc->getDst()->bestMetric();
    if (metric >= 0) {
      if (arc->metric < 0 || betterMetric(metric, arc->metric)){
	arc->metric = metric;
      }
      if (bestMetric < 0 || betterMetric(metric, bestMetric)){
	bestMetric = metric;
      }
    }
  }

  inPath = false;
  nodeMetric = bestMetric;
  //  return metricCombine(bestMetric,label->metric/100);
  return bestMetric;
}

// Since all the children of an AndNode are required for the attack 
// to be successful, the best metric corresponds to the ~combined~
// value of all the outgoing arcs' weights
float AndNode::bestMetric()
{
  float combinedMetric = IDENTITY_METRIC;
  // Recursively call on all the children
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()){
    float metric = arc->getDst()->bestMetric();
    if (metric >= 0){
      if (arc->metric < 0 || betterMetric(metric, arc->metric)){
	arc->metric = metric;
      }
      combinedMetric = metricCombine(combinedMetric, metric);
    }
    else{
      return -1;
    }
  }
  if (useRuleMetrics){
    return metricCombine(combinedMetric, metric);
  }
  else{
    return combinedMetric;
  }
}

float LeafNode::bestMetric()
{
  if (label->metric < 0){
    return IDENTITY_METRIC;
  }
  else{
    return label->metric;
  }
}

void OrNode::pruneUselessEdges()
{
  // If we have already processed this node, return
  if (pruned == Useless){
    return;
  }
  
  pruned = Useless;

  QueueItem<Arc> *arcItemNext = NULL;
  for (QueueItem<Arc> *arcItem = outGoing.getheadQitem(); 
       arcItem != NULL ; 
       arcItem = arcItemNext) {
    arcItemNext = outGoing.getnextQitem(arcItem);
    Arc *arc = outGoing.getitem(arcItem);
    if (arc->weight < 0) {
      outGoing.remove(arcItem);
    }
    else{
      arc->getDst()->pruneUselessEdges(); 
    }
  }
}

void AndNode::pruneUselessEdges()
{
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    arc->getDst()->pruneUselessEdges();
  }
}

void LeafNode::pruneUselessEdges()
{}


int OrNode::CountAndNodes()
{
  int sum_children = 0;

  if( inPath ) return 0;
  if( visited ) return 0;
  inPath = true;                       
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    sum_children += arc->getDst()->CountAndNodes();
  }
  inPath = false;
  visited = true;
  return sum_children;
}

int AndNode::CountAndNodes()
{
  int sum_children = 0;

  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    sum_children += arc->getDst()->CountAndNodes();
  }
  return sum_children+1;
}


int Node::CountAndNodes()
{
  return 0;
}

void OrNode::dfs(dfsAlgorithm alg){
  if (dfsInPath || dfsCounter == currentCounter) return;
  dfsInPath = true;

  /* preprocessing the node */
  switch(alg){
  case reAssignNodeNum:
    nodeNum = currentNodeNum++;
    break;
  }

  /* Recursively call each child */
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    /* preprocessing an arc */
    switch(alg){
    case reAssignNodeNum:
      break;
    }

    /* recursively call dfs on the child */
    arc->getDst()->dfs(alg);

    /* postprocessing an arc */
    switch(alg){
    case reAssignNodeNum:
      arc->arcNum = currentArcNum++;
      break;
    }
  }
  /* postprocessing the node */
  switch(alg){
  case reAssignNodeNum:
    //    cerr << nodeNum << ": " << label->key << endl;
    break;
  }
  dfsInPath = false;
  dfsCounter = currentCounter;
  return;
}

void AndNode::dfs(dfsAlgorithm alg){

  /* preprocessing the node */
  switch(alg){
  case reAssignNodeNum:
    // what is parentNodeNum used for? -- Simon
    nodeNum = currentNodeNum++;
    parentNodeNum = -1;
    break;
  }

  /* Recursively call each child */
  for (Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    /* preprocessing an arc */
    switch(alg){
    case reAssignNodeNum:
      break;
    }

    /* recursively call dfs on the child */
    arc->getDst()->dfs(alg);

    /* postprocessing an arc */
    switch(alg){
    case reAssignNodeNum:
      arc->arcNum = currentArcNum++;
      break;
    }
    /* recursively call dfs on the child */
  }

  /* postprocessing the node */
  switch(alg){
  case reAssignNodeNum:
    //    cerr << nodeNum << ": " << data.ruleList.rules[rulenum] << endl;
    break;
  }
  return;
}

void LeafNode::dfs(dfsAlgorithm alg){
  if (dfsCounter == currentCounter) return;
  switch(alg){
  case reAssignNodeNum:
    nodeNum = currentNodeNum++;
    //    cerr << nodeNum << ": " << label->key << endl;
    break;
  }
  dfsCounter = currentCounter;
  return;
}



void OrNode::Render(renderMode mode, int indent)
{
  if(rendered) {
    draw_a_link(mode, indent, nodeNum, label );
    return;
  }
  rendered = true;
  label->Render(mode, indent, nodeNum, outGoing.size());
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    arc->getDst()->Render(mode, indent +1);
  }
}

void AndNode::Render(renderMode mode, int indent)
{
  RenderRule(mode,  indent, rulenum, nodeNum);
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    arc->getDst()->Render(mode, indent +1);
  }
}

void LeafNode::Render(renderMode mode, int indent)
{
  label->Render(mode, indent, nodeNum);
}

void Arc::Render(arcLabelMode mode){
  switch(mode){
  case WEIGHT:
    cout << src->nodeNum << "," << dst->nodeNum << "," << weight << endl;
    break;
  case NUMBER:
    cout << src->nodeNum << "," << dst->nodeNum << ", E" << arcNum << endl;
    break;
  case METRICMODE:
    cout << src->nodeNum << "," << dst->nodeNum << "," << metric << endl;
    break;
  case NONE:
    cout << src->nodeNum << "," << dst->nodeNum << "," << endl;
  }
}

void Fact::Render( renderMode mode, int indent, int nodenum, int size)
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   const char symbol1[] = "|--";
   const char symbol2[] = "||--";

   switch (mode) {
      case  TEXT:
        cout << indentation  << "<" << nodenum << ">" ;
        if( size == 1)
              cout << symbol1;
        else
              cout << symbol2;
        cout << key << endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

void Fact::Render(renderMode mode, int indent, int nodeNum)
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   switch (mode) {
      case  TEXT:
        cout << indentation << "[" << nodeNum <<"]-"
             << key <<  endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

void Fact::Render(renderMode mode, int indent)
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   switch (mode) {
      case  TEXT:
        cout << indentation << "[]-"
             << key <<  endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

void RenderRule( renderMode mode, int indent, int rulenum )
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   switch (mode) {
      case  TEXT:
        cout << indentation << "RULE " << rulenum << " : " 
             << data.ruleList.rules[rulenum] << endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

void RenderRule( renderMode mode, int indent, int rulenum, int nodeNum )
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   switch (mode) {
      case  TEXT:
        cout << indentation << "(" << nodeNum << ") " << "RULE " << rulenum << " : " 
             << data.ruleList.rules[rulenum] << endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

void draw_a_link( renderMode mode, int indent, int nodeNumber, Fact *label)
{
   string indentation ;
   for ( int i =0; i< indent; i++) { indentation += indentStep; }

   switch (mode) {
      case  TEXT:
        cout << indentation << label->key 
             << "==><" << nodeNumber << ">" << endl;
      break;
  
      case HTML:
      break;
      default:
      break;
   };
}

bool OrNode::Render2(arcLabelMode mode)
{
   if(!rendered) {
      rendered = true;
      outputVertex(label->key, label->metric);
      for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()){
	if (arc->getDst()->Render2(mode))
	  arc->Render(mode);
      }
   }
   return true;
}

bool AndNode::Render2(arcLabelMode mode)
{
   ostringstream temp;
   temp << "RULE " << rulenum  << " (" << data.ruleList.rules[rulenum] << ")";
   outputVertex(temp.str(), metric);
   for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
     if (arc->getDst()->Render2(mode))
       arc->Render(mode);
   }
   return true;
}

bool LeafNode::Render2(arcLabelMode mode)
{
  if (!noSink){
    if(!rendered) {
      rendered = true;
      outputVertex(label->key, label->metric);
    }
    return true;
  }else
    return false;
}

int OrNode::TransformToCNF(int parent)
{
  ostringstream derFact;

  // If first visit to this node
  if(cnfNum == 0) {
    // Set CNF id number to current counter value, then increment counter
    cnfNum = ++cnfCounter;
    derivedCounter++;

    // If vector full, double size to make space for more nodes
    if( mapCNF.size() == cnfNum+1 ) {
      mapCNF.resize(2*mapCNF.size());
    }
    if( mapDerived.size() == derivedCounter+1 ) {
      mapDerived.resize(2*mapDerived.size());
    }
    string tuple = label->predicate->predicate + "(" + label->arguments + ")";
    derFact << "derived_fact( " << cnfNum << ", " << tuple << ")";
    mapCNF[cnfNum] = "derived<<>>" + tuple;
    mapDerived[derivedCounter] = derFact.str();  

    // Transform each child (AndNode) recursively
    for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
      arc->getDst()->TransformToCNF(cnfNum);
    }
  }
  // Return cnf id number
  return cnfNum;
}

int AndNode::TransformToCNF(int parent)
{
  stringstream clause;
  // Build CNF clause from children, using their cnfNums
  for(Arc *arc=outGoing.gethead(); arc != NULL; arc=outGoing.getnext()) {
    // Write cnfNum for each child to file
    clause << - arc->getDst()->TransformToCNF(0) << " ";
  }
  // End line with parent cnfNum & "0", print to file
  clause << parent << " 0";
  
  // If vector full, double size to make space for more clauses
  if(mapClauses.size() == clauseCounter+1) {
    mapClauses.resize(2*mapClauses.size());
  }
  mapClauses[++clauseCounter] = clause.str();

  // AndNode has no cnf number, so return zero
  return 0;
}

int LeafNode::TransformToCNF(int parent)
{
  ostringstream primFact;

  // If first visit, assign value to cnfNum & add to mapping vector
  if(cnfNum == 0) {
    cnfNum = ++cnfCounter;
    primitiveCounter++;
    // If vector full, double size to make space for more nodes
    if( mapCNF.size() == cnfNum+1 ) {
      mapCNF.resize(2*mapCNF.size());
    }
    if( mapPrimitives.size() == primitiveCounter+1 ) {
      mapPrimitives.resize(2*mapPrimitives.size());
    }
    string tuple = label->predicate->predicate + "(" + label->arguments + ")";
    primFact << "primitive_fact( " << cnfNum << ", " << tuple << ")";
    mapCNF[cnfNum] = "primitive<<>>" + tuple;
    mapPrimitives[primitiveCounter] = primFact.str();
    
  }
  // LeafNode has no children, so no recursive calls
  // Simply return value to parent AndNode
  return - cnfNum;
}

void OrNode::outputVertex( string description, float metric )
{
  if (displayMetric){
    if (metric < 0){
      metric = 0;
    }
    cout << nodeNum << ",\"" << description << "\",\"OR\"," << metric << endl;
  }
  else{
    cout << nodeNum << ",\"" << description << "\",\"OR\"" << endl;
  }
  return;
}

void AndNode::outputVertex( string description, float metric )
{
  if (displayMetric){
    cout << nodeNum << ",\"" << description << "\",\"AND\"," << metric << endl;
  }
  else{
    cout << nodeNum << ",\"" << description << "\",\"AND\"" << endl;
  }
  return;
}

void LeafNode::outputVertex( string description, float metric )
{
  if (displayMetric){
    if (metric < 0){
      metric = 1;
    }
    cout << nodeNum << ",\"" << description << "\",\"LEAF\"," << metric << endl;
  }
  else{
    cout << nodeNum << ",\"" << description << "\",\"LEAF\"" << endl;
  }
  return;
}

OrNode* nodeContainer::addOrNode(string &key, Fact *label)
{
   OrNode *nd ;
   NodeMap::iterator i;

   i= nodes.find( key );

   if( i  == nodes.end() ) {
       nd = new OrNode(label) ;
       if( nd == NULL) {
          return NULL;
       }
       graph_data::nodeCount++;
       nd->nodeNum = graph_data::nodeCount;
       nodes[ key ] = nd;
       graph_data::orNodeCount++;
   }
   else {
       nd = (OrNode *)i->second;
   }
   
   return nd;
}

LeafNode* nodeContainer::addLeafNode(string &key, Fact *label)
{
   LeafNode *nd ;
   NodeMap::iterator i;

   i= nodes.find( key );

   if( i  == nodes.end() ) {
       nd = new LeafNode(label) ;
       if( nd == NULL) {
          cerr << "Failed to create new leaf node\n";
          exit(1);
       }
       graph_data::nodeCount++;
       nd->nodeNum = graph_data::nodeCount;
       nodes[ key ] = nd;
       graph_data::leafNodeCount++;
   }
   else {
       nd = (LeafNode *)i->second;
   }
   return nd;
}



// Procedure for processing command-line arguments
void process_args(int argc, char *argv[]){
  for (int i=1; i < argc; i++){
    if (*argv[i] == '-'){
      if (!strcmp(argv[i], "-l")){
	arc_and_node = true;
      }
      else if (!strcmp(argv[i], "--arcNum")){
	arc_mode = NUMBER;
      }
      else if (!strcmp(argv[i], "--arcMetric")){
	arc_mode = METRICMODE;
      }
      else if (!strcmp(argv[i], "--arcWeight")){
	arc_mode = WEIGHT;
      }
      else if (!strcmp(argv[i], "--noSink")){
	noSink = true;
      }
      else if(!strcmp(argv[i], "-p")){
	prune_option = nonSimple;
      }
      else if(!strcmp(argv[i], "-h")){
	print_usage();
      }
      else if(!strcmp(argv[i], "-t")){
	test = true;
      }
      else if(!strcmp(argv[i], "-s")){
	buildCNF = true;
      }
      else if(!strcmp(argv[i], "-m")){
	useMetrics = true;
      }
      else if(!strcmp(argv[i], "-rm")){
	useRuleMetrics = true;
      }
      else if(!strcmp(argv[i], "-nm")){
	displayMetric = false;
      }
      else{
	print_usage();
      }
    }
    else{
      if (tracefile_name){
	print_usage();
      }
      else{
	tracefile_name = argv[i];
      }
    }
  }
}

void print_usage(){
  cerr << "Usage: attack_graph [options] tracefile_name" << endl;
  cerr << "Options: " << endl;
  cerr << "    -l:  List nodes and arcs as separate files." << endl;
  cerr << "    -p:  Only output simple paths." << endl;
  cerr << "    -t:  Test mode." << endl;
  cerr << "    -s:  Run SAT solver." << endl;
  exit(-1);
}

int main(int argc, char *argv[]  )
{
   //cout << "Starting attack_graph builder.\n" << argc << endl;
   if (argc < 2){
     cout << "Usage attack_graph trace_file.\n";
     return -1;
   }
   else{
     process_args(argc, argv);
   }


   // parse the input, fill facts, traceSteps and ruleList objects
   #ifdef LINUX
   yyin = fopen( tracefile_name,"r");
   if (yyin == NULL) {
     cout << "Cannot open trace file " << tracefile_name << endl;
     return -1;
   }
   #else
   *my_ptr = fopen( tracefile_name,"r");
   if (*my_ptr == NULL) {
     cout << "Cannot open trace file " << tracefile_name << endl;
     return -1;
   }
   #endif

   if (yyparse() != 0){
     cerr << "Error in parsing trace_output.P" << endl;
     return -1;
   }


   //dump_tables();
   //
   if (data.goals.size() == 0){
     cerr << "No attack paths found.\n";
     return 1;
   }

   if (build_graph())
     return -1;

   if (build_visual(arc_and_node))
     return -1;

   // If SAT-solver option selected and valid attack graph has been generated, write to files
   if (buildCNF) {
     cerr << "Convert graph nodes into CNF clauses, then write to clauses.cnf" << endl;
     build_cnf();
   }

   //   if (test) {
      // extra data on the end
   /* cout << "nodeCount: " <<  graph_data::nodeCount << ", " 
           << "orNodeCount: " <<  graph_data::orNodeCount << ", " 
           << "leafNodeCount: " <<  graph_data::leafNodeCount <<  endl; */
      // wait for some input
      // getchar();
      //}

   return 0;
}

int build_graph(void)
{
   // loop through all the unique trace steps 
   traceStepMap::iterator i,j;
   traceStepMap *Map;
   Map = &data.all_trace_steps.traceSteps;
   for( i=Map->begin(); i != Map->end(); )
   {
      string ts_key = i->first;
      TraceStep *ts = i->second;
      int num = ts->ruleNum;
      Conjunct *c = ts->conjunct;
      Fact *f = ts->fact;
      float metric = ts->metric;

      // free up the tracestep space, we won't need it again
      delete ts;
      j=i;
      i++;
      Map->erase( j );

      string fact_key = f->key;
      OrNode *orNode = data.all_or_nodes.addOrNode(fact_key, f);
      AndNode *andNode = new AndNode(num, metric);  

      if( andNode == NULL || orNode == NULL) {
          cerr << "Failed to create new node\n";
          return -1;
      }
      data.all_and_nodes.nodeList.add( *andNode );
       graph_data::nodeCount++;
       andNode->nodeNum = graph_data::nodeCount;
         andNode->parentNodeNum = orNode->nodeNum;
      orNode->outGoing.add(*(new Arc(orNode, andNode)));
      for( Fact *fa= c->factList.gethead(); fa >0; fa = c->factList.getnext()) {
           fact_key = fa->key; 
           Node *newNode;
           Type factType = fa->predicate->type; 
           if( factType == primitive) {
               newNode = data.all_leaf_nodes.addLeafNode(fact_key, fa); 
           }
           else if( factType == derived) {
               newNode = data.all_or_nodes.addOrNode(fact_key, fa); 
           }
	   if (factType == primitive || factType == derived){
	     andNode->outGoing.add(*(new Arc(andNode, newNode)));
	   }
      }
      // free up the conjunction space, we won't need it again
      delete c;
   }

   //Populating the head nodes
   NodeMap::iterator k;
   for (k = data.goals.begin(); k != data.goals.end(); k++) {
     string fact_key = k->first;
     Node *headNode = data.all_or_nodes.nodes[fact_key];
     if (headNode != NULL){
       data.goals[fact_key] = headNode;
     }
     else{
       cerr << "Warning: attack goal "<<fact_key<<" was not computed."<<endl;
     }
   }

   //Perform specified pruning
   switch(prune_option){
   case noPrune: 
     break;
     /*
   case unFounded: 
     data.headNode->RemoveUnfoundedEdges();
     break;
     */
   case nonSimple:
     for (k = data.goals.begin(); k != data.goals.end(); k++) {
       Node *headNode = k->second;
       if (headNode != NULL){
	 headNode->allSimplePaths();
       }
     }
     for (k = data.goals.begin(); k != data.goals.end(); k++) {
       Node *headNode = k->second;
       if (headNode != NULL){
	 headNode->pruneUselessEdges();
       }
     }
   default:
     break;
   }
   
   /*Reassign node number after pruning */
   currentCounter++;
   currentNodeNum=1;
   currentArcNum = 1;
   for (k = data.goals.begin(); k != data.goals.end(); k++) {
     Node *headNode = k->second;
     if (headNode != NULL){
       headNode->dfs(reAssignNodeNum);
     }
   }

   //Assign metrics for AssetRank
   if (useMetrics){
     cerr << "Computing metrics..." << endl;
     for (k = data.goals.begin(); k != data.goals.end(); k++) {
       Node *headNode = k->second;
       if (headNode != NULL){
	 headNode->bestMetric();
       }
     }
   }

   return 0;
}

int build_visual(bool arc_and_node)
{
  NodeMap::iterator k;
  for (k = data.goals.begin(); k != data.goals.end(); k++) {
    string fact_key = k->first;
    Node *headNode = k->second;
    if (headNode != NULL){
      if (arc_and_node){
	//	cout << "0," << headNode->nodeNum << ",1" << endl;
	headNode->Render2(arc_mode);
      }
      else{
	// Render the graph. start with zero indentation
	headNode->Render(TEXT, 0);
	cout << endl;
      }
    }
  }
  
  return 0;
}

int build_cnf()
{
  NodeMap::iterator k;
  Node *headNode;

  for (k = data.goals.begin(); k != data.goals.end(); k++) {
     headNode = k->second;
     if(headNode != NULL) {
       headNode->TransformToCNF(0);
     }
  }

  // Write to file primitive_facts.P
  filePrimitiveFacts.open("primitive_facts.P");
  //filePrimitiveFacts << "assert_primitive_facts :- " << endl;
  for(int i = 1; i <= primitiveCounter; i++) {
    filePrimitiveFacts << mapPrimitives[i] << "." << endl;
  }
  //filePrimitiveFacts << "    " << mapPrimitives[primitiveCounter] << "." << endl;
  filePrimitiveFacts.close();

  // Write to file derived_facts.
  fileDerivedFacts.open("derived_facts.P");
  //fileDerivedFacts << "assert_derived_facts :- " << endl;
  for(int i = 1; i <= derivedCounter; i++) {
    fileDerivedFacts << mapDerived[i] << "." << endl;
  }
  //fileDerivedFacts << "    " << mapDerived[derivedCounter] << "." << endl;
  fileDerivedFacts.close();

  // Write to file clauses.cnf
  fileCNF.open("clauses.cnf");
  fileCNF << "p cnf " << cnfCounter << " " << clauseCounter << endl;
  for(int i = 1; i <= clauseCounter; i++) {
    fileCNF << mapClauses[i] << endl;
  }
  fileCNF << "0" << endl;
  fileCNF.close();

  // Write cfnNum/predicate string mapping to mapping.cnf
  cerr << "Write mapping of node number to tuple to mapping.cnf" << endl;
  fileMap.open("mapping.cnf");
  for(int i = 1; i <= cnfCounter; i++) {
    fileMap << i << "<<>>" << mapCNF[i] << endl;
  }
  fileMap.close();

  //system("echo test1");
  //system("force_true.sh primitive_facts.P clauses.cnf mapping.cnf");
  //system("echo test2");

  return 0;
}


//void dump_tables(void)
//{
//      /*
//      cout << "nodeCount=" << data.nodeCount << endl;
//      cout << "goal: " << data.goal->key << endl;

//      int rul =  data.headNode->rulenum;

//      cout << "headNode: " << data.headNode->label->key  << endl;

//      cout << "RULES:\n";

//      for ( int i=0; i<= data.ruleList.count; i++ ) {

//        cout << i << " " ; 

//        if( data.ruleList.rules[ i ] != 0 ) {  

//          cout <<  data.ruleList.rules[ i ] ;

//        }

//        cout  << endl; 

//      }

//      */

//

//      factMap::iterator Fi;

//      NodeMap::iterator Ni;

//      traceStepMap::iterator Ti;

//      factMap *Fmap;

//      traceStepMap *Smap;

//      NodeMap *Nmap;

//

//      /*      

//      cout << "\nUnique FACTS:\n"; 

//      Fmap =  &data.all_facts.facts;

//      cout << Fmap->size() << endl;

//      for (Fi = Fmap->begin() ; Fi != Fmap->end(); Fi++) {

//          cout << Fi->second->key << endl; 

//      }

//      */

//

//      cout << "\nUnique Trace Steps: \n ";

//      Smap =  &data.all_trace_steps.traceSteps;

//      cout << Smap->size() << endl;

//      /*

//      for (Ti = Smap->begin() ; Ti != Smap->end(); Ti++) {

//          cout << Ti->first << endl; 

//          TraceStep *ts = Ti->second;

//           

//          cout << " " << ts->traceNum << " " << ts->ruleNum << " "

//               << ts->fact->key << " \n"; 

//          for( Fact *f= ts->conjunct->factList.gethead(); f >0;

//                                         f= ts->conjunct->factList.getnext()){

//               cout << " " << f->key << endl;

//          }

//          cout << endl;

//      }

//

//      cout << "\nOR nodes:\n"; 

//      Nmap =  &data.all_or_nodes.nodes;

//      for (Ni = Nmap->begin() ; Ni != Nmap->end(); Ni++) {

//          Node *no = Ni->second; 

//          Queue<Node> *q = &no->children; 

//          cout << "*OR Node: " << no->nodeNum 

//               << " " << no->label->key ; 

//          cout << "\nchildren: (" << q->size() << ")" << endl;

//          for(Node *nc = q->gethead(); nc >0; nc = q->getnext()){

//               cout << nc->nodeNum << " " << nc->type << endl;

//          }

//      }

//

//      cout << "\nAND nodes:\n"; 

//      Queue<Node> nq =  data.all_and_nodes.nodeList;

//      for (Node *no = nq.gethead() ; no >0 ; no = nq.getnext()) {

//          Queue<Node> *q = &no->children; 

//          q->audit();

//          cout << "*AND Node: " << no->nodeNum 

//               << " " << no->label->key 

//               << " Rule " << no->rulenum << endl; 

//          cout << "children: (" << q->size() << ")" << endl;

//          for(Node *nc = q->gethead(); nc >0; nc = q->getnext()){

//               cout << nc->nodeNum << " " << nc->type << endl;

//          }

//      }

//

//      cout << "\nLEAF nodes:\n"; 

//      Nmap =  &data.all_leaf_nodes.nodes;

//      for (Ni = Nmap->begin() ; Ni != Nmap->end(); Ni++) {

//          Node *no = Ni->second; 

//          Queue<Node> *q = &no->children; 

//          cout << "*LEAF Node: " << no->nodeNum 

//               << " " << no->label->key;

//          cout << " children: (" << q->size() << ")" << endl;

//          for(Node *nc = q->gethead(); nc >0; nc = q->getnext()){

//               cout << nc->nodeNum << " " << nc->type << endl;

//          }

//      }

//      */

//}

//

//

//

