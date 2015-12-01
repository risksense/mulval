#!/usr/bin/python

import string
import sys
import os

predecessors = { }
successors = { }
orNodes = set([ ])
andNodes = set([ ])
steps = { }

dominators = { }
postdominators = { }
transitiveDominators = { }
transitivePostdominators = { }

numNodes = 0
dfnum = { }
semi = { }
parent = { }
ancestor =  { }
vertex = [ ]
bucket = { }

################################################################################################

def DFS ( parentNode, node ) :
    global dfnum, numNodes, vertex, bucket, successors

    if not dfnum.has_key( node ) :
        dfnum[ node ] = numNodes
        vertex.append( node ) # will be placed in slot indexed by numNodes
        bucket[ node ] = set([ ]) # create empty set as bucket for each node
        numNodes = numNodes + 1 # increment counter for number of nodes

        if not parentNode == None :
            parent[ node ] = parentNode
        for child in successors[ node ] :
            DFS( node, child )

################################################################################################

def ancestorWithLowestSemi(v):
    global ancestor, dfnum, semi

    u = v
    while ancestor.has_key(v) : 
        if dfnum[semi[v]] < dfnum[semi[u]] :
            u = v
        v = ancestor[v]
    return u

################################################################################################

def findDominators( ) :
    global root, numNodes, parent, dfnum, ancestor, semi, predecessors, successors, vertex, bucket

    numNodes = 0
    dfnum = { }
    semi = { }
    parent = { }
    ancestor = { }
    vertex = [ ]
    bucket = { }

    samedom = { }
    idom = { }

    # Use depth-first search to number nodes
    DFS(None, root)
    
    for i in range(numNodes-1, 0, -1) :
        node = vertex[i]
        parentNode = parent[ node ]
        s = parentNode
        
        for v in predecessors[ node ]:
            if dfnum[ v ] <= dfnum[ node ] :
                s2 = v
            else :
                s2 = semi[ancestorWithLowestSemi(v)]
            if dfnum[ s2 ] < dfnum[ s ] :
                s = s2
                    
        semi[ node ] = s
        bucket[s] = bucket[s] | set([ node ])
                    
        ancestor[ node ] = parentNode   # equivalent of link(parentNode, node)
                    
        for v in bucket[ parentNode ] : 
            y = ancestorWithLowestSemi(v)
            if semi[y] == semi[v] : 
                idom[v] = parentNode
            else : 
                samedom[v] = y
                            
        bucket[ parentNode ] = set([ ]) # reset parentNode bucket to empty set
                            
        for i in range(1, numNodes) : 
            node = vertex[i]
            if samedom.has_key( node ) and idom.has_key( samedom[node] ) : 
                idom[ node ] = idom[ samedom[ node ] ]
                                    
    return idom

################################################################################################

def reversePredsSuccs( ) :
    global predecessors, successors

    tempSuccessors = { }
    tempPredecessors = { }

    for node in orNodes:
        tempSuccessors[node] = set([ ])
        tempPredecessors[node] = set([ ])

    for node in successors.keys() :
        for succ in successors[node] :
            tempSuccessors[succ].add(node)
    successors = tempSuccessors

    for node in predecessors.keys() :
        for pred in predecessors[node] :
            tempPredecessors[pred].add(node)
    predecessors = tempPredecessors

################################################################################################

def getTransitiveDominators( node ) :
    global dominators, transitiveDominators

    if not node in transitiveDominators.keys( ) :
        transitiveDominators[node] = set( )

        if node in dominators.keys( ) : # if node has a dominator (not root node)
            transitiveDominators[node].add(dominators[node])
            transitiveDominators[node].update( getTransitiveDominators( dominators[node] ) )

    return transitiveDominators[node]

################################################################################################

def getTransitivePostdominators( node ) :
    global postdominators, transitivePostdominators

    if not node in transitivePostdominators.keys( ) :
        transitivePostdominators[node] = set( )

        if node in postdominators.keys() : 
            transitivePostdominators[node].add(postdominators[node])
            transitivePostdominators[node].update( getTransitivePostdominators( postdominators[node] ) )

    return transitivePostdominators[node]

################################################################################################
################################################################################################

# Retrieve file data
verticesFile = open('VERTICES.CSV', 'r')
verticesFileLines = verticesFile.readlines()
verticesFile.close()
for line in verticesFileLines :
    # Read line from file, split into various values
    pieces = line.strip().split(',')
    count = len(pieces)
    if count == 1 : # line is empty (no more data - break from loop)
        break

    nodeID = pieces[0] 
    nodeText = ''.join(pieces[1:count-2]).strip('"')
    nodeType = pieces[count-2].strip('"')
    # NOT USED - nodeVal = float(pieces[count-1])

    # If OR/AND-node, add to node sets
    if nodeType == 'OR' :
        orNodes.add(nodeID)
    elif nodeType == 'AND' :    
        andNodes.add(nodeID)
    predecessors[nodeID] = set([ ])
    successors[nodeID] = set([ ])
verticesFile.close()

arcsFile = open('ARCS.CSV', 'r')
arcsFile.readline() # ignore first line in file
arcsFileLines = arcsFile.readlines()
arcsFile.close()
for line in arcsFileLines:
    # Read line from file, split into various values
    pieces = line.strip().split(',')
    count = len(pieces)
    # RS 06-Jan-2009: Added next if statement to skip over goal identifiers
    if pieces[0] == '0':  # 0 is just a goal identifier
        continue        # Skip to next line

    if count == 1 : # line is empty (no more data - break from loop)
        break

    src = pieces[0]
    dst = pieces[1]
    # weight is third piece, not used currently
    if dst in (orNodes | andNodes) : #dst is *not* a LEAF-node
        # Reverse edges
        predecessors[src].add(dst)
        successors[dst].add(src)
arcsFile.close()

# Create virtual root node, initialize values
root = '0'
predecessors[root] = set([ ])
successors[root] = set([ ])
orNodes.add(root)

goal = '1'

# Remove AND-nodes, connect OR-nodes directly
for a in andNodes:
    s = successors[a].pop() # get (one & only) successor for AND-node a
    predecessors[s].remove(a) # remove a as predecessor to s
    # No predecessors (since leaf nodes removed)
    if len( predecessors[a] ) == 0: 
        predecessors[s].add(root) # Add root as predecessor
        successors[root].add(s)
        steps[(root,s)] = a
    # Exactly one predecessor
    elif len( predecessors[a] ) == 1:
        p = predecessors[a].pop()  # Get predecessor p
        successors[p].remove(a) # Remove a as successor of p
        successors[p].add(s)     # Add s as successor of p
        predecessors[s].add( p ) # Add p as predecessor of s
        steps[(p,s)] = a
    # Else, multiple predecessors - form merge node
    else:
        # Build merge node id m
        m = ''
        for p in predecessors[a]:
            m += p + ','
        m = m[:len(m)-1] # remove last comma
        # Add m to orNodes set
        orNodes.add(m)
        predecessors[m] = set( )
        # Add m to appropriate sets
        for p in predecessors[a]:
            successors[p].remove(a)
            successors[p].add(m)
            predecessors[m].add(p)
            steps[(p,m)] = a
        predecessors[a] = set( )
        predecessors[s].add(m)
        successors[m] = set([ s ])
        steps[(m,s)] = a
        
# Get dominators
dominators = findDominators()

# Post-dominators
# REVERSE PRED/SUCC DATA
reversePredsSuccs( )

root = goal
postdominators = findDominators()

root = '0'
goal = '1'
reversePredsSuccs( )

# Transitive domination
for i in orNodes :
    getTransitiveDominators( i )

# Transitive postdomination
for i in orNodes :
    getTransitivePostdominators( i )

####### START TRIMMING ########

# Trim based on domination relationships

uselessNodes = set( )

def trimBack( node ) :
    global predecessors, successors, uselessNodes

    # RS 06-Jan-2009: Changed for loop to work with copy because nodes are
    # removed in the loop.
    # Original: for p in predecessors[ node ] :
    for p in predecessors[ node ].copy() :
        uselessNodes.add( steps[(p,node)] )
        predecessors[node].remove(p)
        successors[p].remove(node)
        if successors[p] == set( ): # if no other "next steps"
            uselessNodes.add(p)
            trimBack(p)

# Check if trim-back needed
for (source,dest) in steps.keys( ) :
    # Make sure step not already trimmed
    if source in predecessors[dest] and dest in successors[source]:
        # Check if destination dominates source or source post-dominates destination
        if dest in transitiveDominators[source] or source in transitivePostdominators[dest]:
            uselessNodes.add(steps[(source,dest)]) # associated AND-node is useless
            predecessors[dest].remove(source) # Remove
            successors[source].remove(dest)   # Remove
            if successors[source] == set( ) and source is not goal : # if no other "next steps"
                uselessNodes.add(source) # source is useless
                trimBack(source) # Remove node, keep checking backward

usefulNodes = set( )


arcsFile = open( 'ARCS.CSV', 'w' )
arcsFile.write( '0,1,1\n' )
for line in arcsFileLines:
    # Split line into pieces
    pieces = line.strip().split(',')

    src = pieces[0]
    dst = pieces[1]

    # If edge contains only "useful" nodes
    if not ( src in uselessNodes or dst in uselessNodes ) :
        usefulNodes.update( [src,dst] )
        arcsFile.write( line )
arcsFile.close()

verticesFile = open( 'VERTICES.CSV', 'w' )
for line in verticesFileLines :
    # Split line into pieces
    pieces = line.strip().split(',')

    # If this is a useful node
    if pieces[0] in usefulNodes :
        verticesFile.write( line )
verticesFile.close()
