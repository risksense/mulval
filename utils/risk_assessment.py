#!/usr/bin/python

from sets import Set
from sets import ImmutableSet
import string
import sys
import os
from datetime import datetime

orNodes = Set([ ])
andNodes = Set([ ])
cycleNodes = Set([ ])
irv = { }
preds = { }
succs = { }
branchNodes = Set([ ])
nodeNames = { }

cycleDependencies = { }
cycleData = { }

paths = { }

phi = { }
psi = { }
chi = { }
delta = { }

# Variables used in Tarjan's algorithm
cycles = [ ]
stack = [ ]
indices = { }
lowlink = { }
tarjanIndex = 0

################################################################################
##  Functions defined for calculation over non-cyclic nodes
################################################################################

# Risk assessment of non-cyclic nodes
def evalRisk ( nodeSet ) :
    global phi, chi, delta

#    print "* Starting evalRisk..."
    # Exactly one node in nodeSet
    if len(nodeSet) == 1 : 
        n = nodeSet.pop( )
        if n in phi.keys( ) :
            return phi[n]
        if -n in phi.keys( ) :
            return 1 - phi[-n]
        # One of the two above cases should catch, so this is an error warning:
        print "ERROR: No phi value found for " + str(n)
        sys.exit(0)
    
    # Multiple nodes in nodeSet
    key = ImmutableSet(nodeSet)

    # Return saved value, if one exists
    if key in phi.keys( ) :
        return phi[key]

    # Otherwise, find d-separating set and calculate
    dSet = Set([ ]) 
    for m in nodeSet : # loop over each node in nodeSet
        for n in (nodeSet - Set([m])) : # loop over all *other* nodes
            m = abs(m)
            n = abs(n)
            dSet = dSet | ( chi[m] & chi[n] )
            if n in chi[m] and n in branchNodes :
                dSet.add( n )
#    print "dSet( " + str(nodeSet) + " ) => " + str(dSet)

    cycSet = Set([ ]) # set of cyclic exit nodes in dSet
	# Bug fix -- still trouble handling cycles as predecessors?
    '''
    for c in dSet & cycleNodes: # for each abstract cyclic node in dSet
        cycSet.add(c)
        for n in nodeSet: # for each node with d in chi[n]
#            stop = True
            n2 = abs(n)
            if c in chi[n2]:
                dSet.update( cycleDependencies[(n2,c)].copy() )
#                print "Add " + str(cycleDependencies[(n2,c)].copy()) + " to dSet for node " + str(n2)
    '''
    dSet.difference_update( cycleNodes ) # remove abstract cycle nodes
                    
    if root in dSet:
        print "ERROR: root node should not be in any dSet!"
        sys.exit(0)

#    print "-> d-separating set for node set " + str(nodeSet) + " is " + str(dSet)
    if cycSet: # if cyclic exit nodes affect this node
        c = cycSet.pop() # get cycle node from cycSet
        #paths = cyclePaths[c] # get paths for this cycle
        answer = 0
        sumSet = getSummationValues( dSet.copy() )
        for d in sumSet:
#            print "Call evalCondRisk( " + str(d.copy()) + ", " + str(nodeSet.copy()) + " ) * evalRiskCycleExit( " + str(c) + ", " + str(d.copy()) + " )"
            temp = evalCondRisk( d.copy(), nodeSet.copy() ) * evalRiskCycleExit( c, d.copy() )
#            print temp
            answer += temp
    elif dSet: # if d-separating nodes
        answer = 0
        sumSet = getSummationValues( dSet.copy() )
#        print "--> summation set for d-set " + str(dSet) + " is " + str(sumSet)
        for d in sumSet :
#            print "1: Call evalCondRisk ( " + str(d) + ", " + str(nodeSet) + ")"
            temp = evalCondRisk( d.copy(), nodeSet.copy() ) * evalRisk( d.copy() )
#            print ":: psi(" + str(d) + ", " + str(nodeSet) + ") = " + str(getPsiValue( d, nodeSet ))
            answer += temp
    else: # no d-separating set -- independent nodes
        answer = 1
        for n in nodeSet: # Find product of probabilities for all nodes
            answer *= evalRisk(Set([n]))

    phi[key] = answer
    return answer

################################################################################

# Conditional risk assessment of non-cyclic nodes
def evalCondRisk ( dSet, nodeSet ) :
    global psi, phi, chi, delta
	
    # If already calculated, return stored answer
    if checkPsi( dSet, nodeSet ) :
        return getPsiValue( dSet, nodeSet )

    # If nodeset has multiple elements
    if len(nodeSet) > 1 :
        answer = 1
        for n in nodeSet :
#            print "2: Call evalCondRisk ( " + str(dSet) + ", " + str(Set([n])) + ")"
            answer *= evalCondRisk(dSet.copy(),Set([n]))
        setPsiValue( dSet, nodeSet, answer )
        return answer
    
    #SHOULDN'T HAPPEN?
    if len(nodeSet) == 0 :
        print "ERROR : nodeSet is EMPTY in function evalCondRisk; dSet = " + str(dSet)
        sys.exit(0)

    # Only one element in nodeset, so get it out as 'n'
    n = nodeSet.pop( )

    # If n is negated
    if n < 0 :
#        print "3: Call evalCondRisk ( " + str(dSet) + ", " + str(Set([abs(n)])) + ")"
        answer = 1 - evalCondRisk(dSet.copy(),Set([abs(n)]))
        setPsiValue( dSet, Set([n]), answer )
        return answer
    
    # Else ( nodeset has one enabled element)
    else :
# Reducing dSet to D is also eliminating all negated nodes that are in chi[n]
# Find a clean way to eliminate nodes not in chi[n] (either pos or neg in dSet)
#        D = dSet & chi[n] # Only keep dSet values that may affect n
        J = Set([ ])
        K = Set([ ])
        for d in dSet :
            if d > 0 : # enabled node
                J.add(d)
            else : # d < 0 : disabled node
                K.add(-d)

        # If n is fixed as true
        if n in J :
            setPsiValue( dSet, Set([n]), 1 )
#            setPsiValue( D, Set([n]), 1 )
            return 1

        # If n or some dominator of n is fixed as false
        if (n in K) or (K & delta[n]) :
            setPsiValue( dSet, Set([n]), 0 )
#            setPsiValue( D, Set([n]), 0 )
            return 0

        if not dSet & chi[n]: # if dSet does not affect n
            return phi[n]

        # If n is an OR-node
        if n in orNodes:
#            print "4: Call evalCondRisk ( " + str(dSet) + ", " + str(getPredsNeg(n)) + ")"
            answer = 1 - evalCondRisk( dSet.copy(), getPredsNeg(n) )
            setPsiValue( dSet, Set([n]),  answer )
#            setPsiValue( D, Set([n]), answer )
            return answer

        # Else (n is an AND-node)
        else :
#            print "5: Call evalCondRisk ( " + str(dSet) + ", " + str(getPreds(n)) + ")"
            answer = irv[n] * evalCondRisk( dSet.copy(), getPreds(n) )
            setPsiValue( dSet, Set([n]),  answer )
#            setPsiValue( D, Set([n]), answer )
            return answer

################################################################################
##  Functions defined for calculation over nodes in a cycle
################################################################################

def evalCycle( ):
    global cycles, phi, chi, delta, orNodes, andNodes, paths

    # Find ready cycle (and additional useful data sets)
    cycle, entryNodes, multiSourceNodes, exitNodes = findReadyCycle( )

    listCycle = list(cycle)
    listCycle.sort()
    print "\nEvaluating cycle " + str(listCycle)
    print "Entry nodes: " + str(list(entryNodes))
    print "Multiple-predecessor OR-nodes:  " + str(list(multiSourceNodes.difference(andNodes)))
    print "Multiple-predecessor AND-nodes: " + str(list(multiSourceNodes.difference(orNodes)))

    for e in entryNodes:
        for succ in getSuccs(e):
            if succ in cycle: # where successor of entry node is in cycle
                tracePaths( succ, Set([ e ]), cycle ) # trace paths beginning here

    # Create representative node for this cycle
    cycleNode = 10001 + len(cycleNodes)
    cycleNodes.add(cycleNode)
    # Save cycle data
    cycleData[cycleNode] = (cycle, entryNodes, paths)
    # Save data for exit nodes
    for n in exitNodes:
        chi[n] = Set([ cycleNode ])
        cycleDependencies[(n,cycleNode)] = Set([n])

    # Print multi-source nodes (just for refrence)
    print "Finished tracing paths"
    for m in multiSourceNodes:
        print "Multi-source > " + str(m) + " - " + str(len(paths[m])) + " partial paths"


    # Solve all multi-source nodes in cycle
    for m in multiSourceNodes: 
        print "***************** Cyclic calculation for node " + str(m) + " *****************"

        partialPaths = paths[m]

        # Find d-separating set over paths to m
        nodeSet = Set([ ])
        dSet = Set([ ])
        for pp in partialPaths:
            # Add nodes seen multiple times
            dSet.update( pp & nodeSet )
            # Track all AND-nodes appearing in paths to m
            nodeSet.update(pp.difference(orNodes))
        #qSet = entryNodes & nodeSet  # Get all entry nodes leading to m
        qSet = entryNodes # all entry nodes?
        dSet.difference_update(qSet) # Remove entry nodes from d-separating set
        # Remove d-separating nodes with probability 1 (can't affect phi[m])
        for d in dSet.copy():
            if irv[d] == 1:
                dSet.remove(d)

        # Show data gathered
        print "Relevant entry nodes: " + str(qSet)
        print "d-separating set:     " + str(dSet)
        print "Paths:                " + str(partialPaths)

        # Evaluate conditional probabiliy of m, given q in qSet and dSet
        qSumSet = getSummationValues(qSet.copy())
        es = qSet #Set([val for val in list(entryNodes) if Set([val]) in qSumSet]) # entry nodes
        res = evalRisk(es) # probability of entry nodes
        if m in orNodes: # OR-node (no irv value)
            #phi[m] = 1 - evalCycleNode( dSet.copy(), 1, Set([ ]), qSumSet, partialPaths )
            recn = 1 - evalCycleNode( dSet.copy(), 1, Set([ ]), qSumSet, partialPaths )
            phi[m] = res * recn
        else: # AND-node (has irv value)
            phi[m] = res * irv[m] * (1 - evalCycleNode( dSet.copy(), 1, Set([ ]), qSumSet, partialPaths ))
        print "phi[" + str(m) + "] = " + str(phi[m])
#        sys.exit(0)
    # For testing purposes
#    sys.exit(0)
    print
    return multiSourceNodes # these nodes have been solved already

################################################################################

def findReadyCycle( ):
    global cycles, stack, indices, lowlink, tarjanIndex

    # Run Tarjan's algorithm to identify cycles in graph
    # Re-initialize variables
    cycles = [ ]
    stack = [ ]
    indices = { }
    lowlink = { }
    tarjanIndex = 0
    # Call function
    tarjan( root )

    # Print data found
#    print "# of cycles = " + str(len(cycles))
#    if cycles : # if any cycles found
#        print "Cycles"
#        for c in cycles :
#            print c,
#            print " -- Size[" + str(len(c)) + "]"
#        print

    # Find unevaluated cycle with all predecessors evaluated
    for cycle in cycles: # loop over all cycles
        cycleReady = True # initialize verification variable
        entryNodes = Set([ ]) # initialize set of nodes entering into cycle
        multiSourceSet = Set([ ]) # initialize set of multiple-predecessor nodes
        for c in cycle: # for every node in cycle
            if c in phi.keys(): 
                cycleReady = False # cycle already solved
            else: # cycle not solved (but maybe not ready)
                predSet = getPreds(c)
                if len(predSet) > 1:
                    multiSourceSet.add(c) # add c as cyclic node with multiple predecessors
                for p in predSet:
                    if not p in cycle:
                        if not p in phi.keys():
                            cycleReady = False # this pred not yet solved
                            break
                        entryNodes.add(p) # add p as entry node into cycle
            if not cycleReady: # this cycle not ready, check next
                break
        if cycleReady: # ready cycle found
            break

    # Identify exit nodes
    exitNodes = Set([ ])
    for c in cycle:
        for s in getSuccs(c):
            if not s in cycle:
                exitNodes.add(c)
                break

    return ( cycle, entryNodes, multiSourceSet, exitNodes )

################################################################################

# Trace non-cycle paths to nodes within cycle
def tracePaths( node, pathSet, cycle ):
    global paths

    # Identify intra-cycle successors not yet in path
    succSet = Set([ ])
    for succ in getSuccs(node):
        if succ in cycle and not succ in pathSet:
            succSet.add(succ)

    # Store partial paths
    if node in paths.keys():
        paths[node].append(pathSet)
    else:
        paths[node] = [ pathSet ]

    # Recursive calls
    for succ in succSet:
        newPathSet = pathSet.copy()
        newPathSet.add(node)
        tracePaths( succ, newPathSet, cycle )

################################################################################

def evalCycleNode( dSet, value, fixedNodes, qSumSet, paths ):
    if dSet: # nodes remaining in d-separating set
        n = dSet.pop() # get node
        pos = irv[n]  # probability that n is true
        neg = 1 - pos # probability that n is false

        answerP = evalCycleNode( dSet.copy(), value*pos, fixedNodes | Set([ n]), qSumSet, paths )
        answerN = evalCycleNode( dSet.copy(), value*neg, fixedNodes | Set([-n]), qSumSet, paths )
        return (answerP + answerN)
    else: # d-separating set is empty
        answer = 0
        for qSet in qSumSet: # consider every permutation of Q
            #print "---------------"
            #print "qSet = " + str(qSet)
            #print "> phi[qSet] = " + str(evalRisk(qSet))
            #print "dSet = " + str(fixedNodes)
            #print "> phi[dSet] = " + str(value)
            prod = 1
            for p in paths:  # consider every path to node m
                temp = ( 1 - evalCyclePath( fixedNodes | qSet, p.copy() ) )
                #print "temp = " + str(temp)
                prod *= temp
            answer += ( evalRisk(qSet) * value * prod )
            #print "answer = " + str(answer)
        return answer

################################################################################

# Returns probability that path succeeds, given fixed nodes
def evalCyclePath( fixedNodes, path ):
    global orNodes
    #print "eCP fixedNodes = " + str(fixedNodes)
    #print "eCP path = " + str(path)

    # Remove OR-nodes from path (they won't affect probability)
    path.difference_update(orNodes)

    # Loop over fixed nodes
    for f in fixedNodes:
        # Remove forced-true nodes from path
        if f > 0:
            path.discard(f) # Will remove f if in path, no error if not in path
        # If negated node is needed in path, return 0 (node unreachable by this path)
        elif f < 0 and -f in path:
            return 0.0

    # Node is reachable by this path, so compute probability that path will succeed
    prob = 1.0
    for p in path:
        prob = prob * irv[p]
    #print "prob = " + str(prob)
    # Return computed probability 
    return prob

################################################################################

# Compute joint probability for set of exit nodes in cycle
def evalRiskCycleExit( cycNode, nodeSet ):

#    print "--- evalRiskCycleExit --- "
#    print "cycNode = " + str(cycNode)
#    print "nodeSet: " + str(nodeSet)

    cycleSet, entryNodes, paths = cycleData[cycNode]

#    print "cycleSet = " + str(cycleSet)
#    print "entryNodes = " + str(entryNodes)
#    print "paths = " + str(paths)
#    print "nodeSet = " + str(nodeSet)

#    print "* PATHS *"
#    for pk in paths:
#        print str(pk) + ": " + str(paths[pk])
#    print "* NODESET -- " + str(nodeSet) + " *"

    nodePaths = { }
    allPaths = [ ]

    for n in nodeSet:
        nodePaths[n] = paths[abs(n)]
        allPaths.extend( paths[abs(n)] )

#    print "relevant paths = " + str(allPaths)

    # Find d-separating set over paths
    seenSet = Set([ ])
    dSet = Set([ ])
    for pp in allPaths: # for all paths
        # Add nodes seen multiple times
        dSet.update( pp & seenSet )
        # Track all AND-nodes appearing in paths to m
        seenSet.update(pp.difference(orNodes))
    qSet = entryNodes & seenSet  # Get all entry nodes leading to m
    dSet.difference_update(qSet) # Remove entry nodes from d-separating set
    # Remove d-separating nodes with probability 1
    for d in dSet.copy():
        if irv[d] == 1:
            dSet.remove(d)

#    print "d-separating set = " + str(dSet)
#    print "relevant entry nodes = " + str(qSet)

    qSumSet = getSummationValues(qSet.copy())
#    print qSumSet

    answer = evalCycleNodeset( dSet.copy(), 1, Set([ ]), qSumSet, nodeSet, nodePaths )
    phi[ImmutableSet(nodeSet)] = answer
#    print "phi of " + str(nodeSet) + " is " + str(answer)

#    print "\nQuitting..."
#    sys.exit(0)
    return answer

################################################################################

def evalCycleNodeset( dSet, value, fixedNodes, qSumSet, nodeSet, nodePaths ):
    if dSet: # nodes remaining in d-separating set
        n = dSet.pop() # get node
        pos = irv[n]  # probability that n is true
        neg = 1 - pos # probability that n is false

        answerP = evalCycleNodeset( dSet.copy(), value*pos, fixedNodes | Set([ n]), qSumSet, nodeSet, nodePaths )
        answerN = evalCycleNodeset( dSet.copy(), value*neg, fixedNodes | Set([-n]), qSumSet, nodeSet, nodePaths )
        return (answerP + answerN)
    else: # d-separating set is empty
        answer = 0
        for qSet in qSumSet: # consider every permutation of Q
#            print "---------------"
#            print "qSet = " + str(qSet)
#            print "> phi[qSet] = " + str(evalRisk(qSet))
#            print "dSet = " + str(fixedNodes)
#            print "> phi[dSet] = " + str(value)
            allprod = 1
            for n in nodeSet:
                prod = 1
#                print "Considering " + str(n)
                for p in nodePaths[n]:  # consider every path to node m
#                    print "Path " + str(p) + " -- ",
                    temp = 1 - evalCyclePath( fixedNodes | qSet, p.copy() )
#                    print temp
                    prod *= temp
#                print "prod(" + str(n) + ") = " + str(1-prod)
                if n > 0: # node enabled
                    allprod *= (1-prod)
                else: # node disabled
                    allprod *= prod
#            print "prob of " + str(nodeSet) + " given " + str(qSet) + " is " + str(allprod)
            answer += ( evalRisk(qSet) * value * allprod )
#            print "answer = " + str(answer)
        return answer


################################################################################
##  Identify strongly-connected components (cycles) within the graph
################################################################################

def tarjan( v ) :
    global tarjanIndex

    indices[v] = tarjanIndex
    lowlink[v] = tarjanIndex
    tarjanIndex += 1

    stack.append(v)

    succSet = getSuccs(v)
    if succSet : # if node v has successors
        for n in succSet :
            if not n in indices.keys() :
                tarjan( n )
                lowlink[v] = min(lowlink[v], lowlink[n])
            elif n in stack :
                lowlink[v] = min(lowlink[v], lowlink[n])
                
    if( indices[v] == lowlink[v] ) :
        cycleSet = Set([ ])
        while True :
            pv = stack.pop()
            cycleSet.add(pv)
            if pv == v :
                break
#        print "CYCLE -- " + str(cycleSet)
        if len(cycleSet) > 1 :
            cycles.append(cycleSet)

################################################################################
##  Helper functions, to minimize code repitition
################################################################################

# Builds set of positive/negative permutations for summation over d-separating set
def getSummationValues( nodeSet ) :
    if not nodeSet : # empty
        return [ ]

    n = nodeSet.pop()
    if nodeSet : # more nodes remaining
        newList = [ ]
        tempList = getSummationValues( nodeSet )
        for t in tempList :
            newList.append( t | Set([ n]) )
            newList.append( t | Set([-n]) )
        return newList
    else : # last node in nodeSet
        return [ Set([n]), Set([-n]) ]

################################################################################
# Functions to return copied sets of immediate predecessors / successors
#   for a single node; also, negated sets of predecessors

# Return all immediate successors for given node
def getSuccs( node ) :
    global succs
    return succs[node].copy()

# Return all immediate predecessors for given node
def getPreds( node ) :
    global preds
    return preds[node].copy()

# Return negation of immmediate predecessors for given node
def getPredsNeg( node ) :
    global preds
    predSet = getPreds(node)
    negPredSet = Set([ ])
    for p in predSet :
        negPredSet.add( -p )
    return negPredSet

################################################################################
# Functions to set, get, and check existence of psi values

# Stores given value as psi result for source/destination pair
def setPsiValue( source, destination, value ) :
    global psi
    psi[ tuple( [ImmutableSet([source]), ImmutableSet([destination]) ] ) ] = value

# Retrieves psi value for source/destination pair
def getPsiValue( source, destination ) :
    global psi
    return psi[ tuple( [ImmutableSet([source]), ImmutableSet([destination])] ) ]

# Checks if psi value already obtained for source/destination pair; returns T/F
def checkPsi( source, destination ) :
    global psi
    if tuple( [ImmutableSet([source]), ImmutableSet([destination])] ) in psi.keys( ) :
        return True
    return False

################################################################################
################################################################################
## Main code block
################################################################################
################################################################################

# Identify and initialize all AND/OR nodes    
verticesFile = open('VERTICES.CSV', 'r')
while verticesFile :
    # Read line from file, split into various values
    pieces = verticesFile.readline().strip().split(',')
    count = len(pieces)
    if count == 1 : # line is empty (no more data - break from loop)
        break

    nodeID = int(pieces[0])
    nodeText = ','.join(pieces[1:count-2]).strip('"')
    nodeType = pieces[count-2].strip('"')
    nodeVal = float(pieces[count-1])
    # If OR/AND-node, add to node sets
    if nodeType == 'OR' or nodeType == 'AND' :   
        nodeNames[nodeID] = nodeText
        preds[nodeID] = Set([ ])
        succs[nodeID] = Set([ ])
        chi[nodeID] = Set([ ])
        delta[nodeID] = Set([ ])
        if nodeType == 'OR':
            orNodes.add(nodeID)
        else : # type == '"AND"'
            andNodes.add(nodeID)
            irv[nodeID] = nodeVal
verticesFile.close()

# Create virtual root node, initialize values
root = 0
preds[root] = Set([ ])
succs[root] = Set([ ])
chi[root] = Set([ ])
delta[root] = Set([ ])
orNodes.add(root)

phi[root] = 1 # need to change if actually keeping graph risk value
#if root in branchNodes :
#    setPsiValue( root, root, 1 )

# Record all edges in approprioate predecessor/successor sets
arcsFile = open('ARCS.CSV', 'r')
#arcsFile.readline() # ignore first line in file
while arcsFile :
    # Read line from file, split into various values
    pieces = arcsFile.readline().strip().split(',')
    count = len(pieces)
    if count == 1 : # line is empty (no more data - break from loop)
        break

    src = int(pieces[0])
    dst = int(pieces[1])
    # weight is third piece, not used currently
    if dst in ( orNodes | andNodes ) : #dst is *not* a LEAF-node
        # Reverse edges
        preds[src].add(dst)
        succs[dst].add(src)
arcsFile.close()

# Add branches from root node
for nd in andNodes :
    if not preds[nd] : # if AND-node has no predecessors
        preds[nd].add(root) # add root as predecessor to node
        succs[root].add(nd) # add node as successor to root

# Identify all branch nodes
for n in orNodes : # consider all OR-nodes
    if len( succs[n] ) > 1 : # if more than one successor
        branchNodes.add(n) # mark as branch node
branchNodes.discard(root) # root should not be marked as a branch node

'''
# Print collected data, for verification
print "** Nodes [" + str(len(orNodes) + len(andNodes)) + "] ** "
for n in orNodes :
    print n
for n in andNodes:
    print str(n) + ", " + str(irv[n])
'''
'''
print "** Edges ** "
for src in succs :
    print str(src) + " -- ",
    for dst in succs[src] :
        print str(dst) + '  ',
    print
'''

#for k in preds.keys():
#	print 'Predecessors of ' + str(k) + ': ' + str(preds[k])

#print "Total number of nodes: " + str(len(orNodes) + len(andNodes))
# Identify all cycles
#tarjan( root )
#print "predecessors of 13 -> " + str(preds[13])
#print "successors of 13 -> " + str(succs[13])

#if cycles : # if any cycles found
#    print "Cycles"
#    for c in cycles :
#        print c,
#        print " -- Size[" + str(len(c)) + "]"
#    print
#else :
#    print "No cycles found"

#sys.exit(0)

# Initialize list of unevaluated nodes
unevaluatedNodes = ( andNodes | orNodes )
unevaluatedNodes.remove(root)
unevaluatedNodes = list(unevaluatedNodes)

# Loop through all unevaluated nodes
while unevaluatedNodes :
    # Find ready node and predecessors; set to variables n, predSet
    n = False
#    remainingNodes = unevaluatedNodes
    rnIndex = 0
    while rnIndex < len(unevaluatedNodes) and not n :
        n = unevaluatedNodes[rnIndex]
        # If not all predecessors evaluated, we cannot evaluate this node
        if not ( getPreds(n) <= Set(phi.keys()) ) :
            # If predecessor has probability 1, n must have probability 1
            if n in orNodes:
                for p in ( getPreds(n) & Set(phi.keys()) ):
                    if ( phi[p] == 1.0 ) :
                        # Assign phi(n) and print to screen
                        phi[n] = 1.0
#                        print 'Predecessors: ' + str(getPreds(n))
                        print "phi[" + str(n) + "] = 1.0 *" #* < " + str(p) + " >"
                        # Remove edges to/from unused predecessors
#                        print "n: " + str(n)
#                        print "p: " + str(p)
#                        print "predset: " + str(getPreds(n))
                        for pd in getPreds(n):
                            if not pd == p:
                                andNodes.remove(pd)
                                succs[pd] = Set([ ])
                                for ppd in getPreds(pd):
                                    succs[ppd].remove(pd)
                                preds[pd] = Set([ ])
                        # Remove other predecessors from set
                        preds[n] = Set([p])
                        # If successor AND-node has multiple preds, remove this one
                        # since it won't affect prob. of sc
                        for sc in getSuccs(n):
                            if len(getPreds(sc)) > 1:
                                preds[sc].remove(n)
                                succs[n].remove(sc)
                        # Set chi / delta values
                        chi[n] = chi[p]   
                        delta[n] = delta[p]
                        if n in branchNodes:
                            setPsiValue( n, n, 1 )
                        # Remove this node from lists
                        #remainingNodes.pop(rnIndex)
                        unevaluatedNodes.pop(rnIndex)
                        # Reset counter, to search for another node
                        rnIndex = -1 # will add one, loop at zero
                        #print 'Predecessors: ' + str(getPreds(n))
            n = False
            rnIndex += 1

            # Recognize where node has probability 1, even with multiple predecessors
#            for p in ( getPreds(n) & Set(phi.keys()) ):
#                if phi[p] == 1.0:
#                    print "Node " + str(n) + " should be assigned probability 1, from pred " + str(p)

    # If ready node is found, evaluated acyclically
    if n : 
        print "Evaluating node " + str(n)
        # Get immediate predecessors of n
        predSet = getPreds(n)
        print 'Predecessors: ' + str(predSet)

        # If node 'n' is an OR-node
        if n in orNodes :
            # Find absolute probability for node n
            phi[n] = 1 - evalRisk ( getPredsNeg(n) )
            print "phi[" + str(n) + "] = " + str(phi[n])

            # Build chi & delta sets
            '''
            # This code segment causing errors in testing, functionality replaced below
            p = predSet.pop() # get one element out of predSet
            chi[n] = chi[p]   # initialize chi function same as predecessor's
            delta[n] = delta[p] # initialize delta function same as pred's
            for p in predSet : # if multiple predecessors
                print "-- p = " + str(p)
                chi[n] = chi[n] | chi[p] # union of all chi[pred]
                delta[n] = delta[n] & delta[p] # intersection of all chi[pred]
                # Check for cycle dependencies; copy data if present
                for c in chi[p] & cycleNodes:
                    print "-- c = " + str(c)
                    if (n,c) in cycleDependencies:
                        cycleDependencies[(n,c)].update( cycleDependencies[(p,c)].copy() )
                    else:
                        cycleDependencies[(n,c)] = cycleDependencies[(p,c)].copy()
            '''
            # BEGIN CORRECTION EDIT #
            chi[n] = Set([ ]) # initalize as empty (will be populated)
            delta[n] = orNodes | andNodes #initialize as all nodes (will be reduced)
            for p in predSet:
                chi[n] = chi[n] | chi[p] # union of all chi[pred]
                delta[n] = delta[n] & delta[p] # intersection of all chi[pred]
                # Check for cycle dependencies; copy data if present
                for c in chi[p] & cycleNodes:
                    if (n,c) in cycleDependencies:
                        cycleDependencies[(n,c)].update( cycleDependencies[(p,c)].copy() )
                    else:
                        cycleDependencies[(n,c)] = cycleDependencies[(p,c)].copy()
            # END CORRECTION EDIT #
            if n in branchNodes :
                setPsiValue( n, n, 1 )

            # Special case: phi[n] = 1
            if phi[n] == 1:
                # If successor AND-node has multiple preds, remove this one
                # since it won't affect prob. of sc
                for sc in getSuccs(n):
                    if len(getPreds(sc)) > 1:
                        preds[sc].remove(n)
                        succs[n].remove(sc)

        # Else (node 'n' is an AND-node)
        else :
            # Special case
            # Remove all predecessors of n with probability 1
            # If this is all preds, phi[n] = 1
            # Else, compute normally
#            for pd in getPreds(n):
#                if phi[pd] == 1.0:
#                    preds[n].remove(pd)
            if not getPreds(n): # set empty
                phi[n] = irv[n]
            else:
                # Get absolute probability
                if( n == 9 ):
					print "Preds[9] = " + str(getPreds(n))
					print "evalRisk(preds) = " + str(evalRisk(getPreds(n)))
                phi[n] = irv[n] * evalRisk( getPreds(n) )
            print "phi[" + str(n) + "] = " + str(phi[n])

            # Build chi & delta sets
            chi[n] = branchNodes & predSet # all branch nodes that are predecessors
            delta[n] = branchNodes & predSet # all branch nodes that are predecessors
            for p in predSet :
                chi[n] = chi[n] | chi[p] # union of all chi[pred]
                delta[n] = delta[n] | delta[p] # union of all chi[pred]
                # Check for cycle dependencies; copy data if present
                for c in chi[p] & cycleNodes:
                    if (n,c) in cycleDependencies:
                        cycleDependencies[(n,c)].update( cycleDependencies[(p,c)].copy() )
                    else:
                        cycleDependencies[(n,c)] = cycleDependencies[(p,c)].copy()

        # Remove node n from set of unevaluated nodes
        unevaluatedNodes.pop(rnIndex)

    # Else ( not n ) - no ready node, so need to evaluate cycle
    else : 
        cycDone = evalCycle() # call evalCycle, get back cyclic set just evaluated
#        for nd in cycDone :
#            print "phi[" + str(nd) + "] = " + str(phi[nd])
        unevaluatedNodes = list(Set(unevaluatedNodes).difference(cycDone)) # remove cyclic nodes from list

# Print results for each node
print
print "***********************************************"
print "Risk assessments for graph nodes"
print "***********************************************"
print "OR-nodes"
lstOr = list(orNodes)
lstOr.sort()
for nd in lstOr :
    print str(nd) + ":\t" + str(phi[nd])
print
print "AND-nodes"
lstAnd = list(andNodes)
lstAnd.sort()
for nd in lstAnd :
    print str(nd) + ":\t" + str(phi[nd])
print
