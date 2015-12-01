#!/usr/bin/python

from sets import Set
import string
import sys

predecessors = { }
successors = { }
subnets = Set([ ])
numNodes = 0
dfnum = { }
semi = { }
parent = { }
ancestor =  { }
vertex = [ ]
bucket = { }

def DFS ( parentNode, node ) :
    global dfnum, numNodes, vertex, bucket, successors

    if not dfnum.has_key( node ) :
        dfnum[ node ] = numNodes
        vertex.append( node ) # will be placed in slot indexed by numNodes
        bucket[ node ] = Set([ ]) # create empty set as bucket for each node
        numNodes = numNodes + 1 # increment counter for number of nodes

        if not parentNode == None :
            parent[ node ] = parentNode
        for child in successors[ node ] :
            DFS( node, child )

def ancestorWithLowestSemi(v):
    global ancestor, dfnum, semi

    u = v
    while ancestor.has_key(v) : 
        if dfnum[semi[v]] < dfnum[semi[u]] :
            u = v
        v = ancestor[v]
    return u

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
    
    for i in range(numNodes-1, 0, -1) : # range N-1 to 1, counting down
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
        bucket[s] = bucket[s] | Set([ node ])
                    
        ancestor[ node ] = parentNode   # equivalent of link(parentNode, node)

        for v in bucket[ parentNode ] : 
            y = ancestorWithLowestSemi(v)
            if semi[y] == semi[v] : 
                idom[v] = parentNode
            else : 
                samedom[v] = y
                            
        bucket[ parentNode ] = Set([ ]) # reset parentNode bucket to empty set
                            
    for i in range(1, numNodes) : # range 1 to N-1
        node = vertex[i]
        if samedom.has_key( node ) : 
            idom[ node ] = idom[ samedom[ node ] ]
                                    
    return idom


# Begin main code block

if( len(sys.argv) == 3 ) :
    inputFile = sys.argv[1]
    outputFile = sys.argv[2]
else :
    sys.exit("Usage : dom.py inputFile outputFile")

# Read inter-subnet transition data from file
fileHandle = open ( inputFile, 'r' )
root = fileHandle.readline().strip()
goal = fileHandle.readline().strip()
fileList = fileHandle.readlines()
fileHandle.close() 

# Build successor/predecessor tables

# Insert virtual root node *vroot* (and replace "real" root)
vroot = 'vroot'
subnets.add(vroot)
successors[vroot] = Set([root])
predecessors[root] = Set([vroot])
root = vroot

# Get all other edges from file data
for fileLine in fileList :
    # Get source & dest nodes, strip off formatting text
    source, dest = fileLine.split(',')
    source = string.lstrip(source, '[').strip()
    dest = string.rstrip(dest, ']\n')
	# Add to subnets set (if needed)
    subnets.add(source)
    subnets.add(dest)
    # Record successor / predecessor relationships
    if successors.has_key(source) :
        successors[source].add(dest)
    else :
        successors[source] = Set([dest])
    if predecessors.has_key(dest) :
        predecessors[dest].add(source)
    else :
        predecessors[dest] = Set([source])

# Add any virtual edges from vroot, as needed
for s in subnets:
    if not predecessors.has_key(s) and s != vroot:
        successors[root].add(s)
        predecessors[s] = Set([root])

# Verify data manually
'''
print "ROOT = ", root
print "GOAL = ", goal
print "SUBNETS"
for s in subnets:
    print s
print "SUCCESSORS"
for s in successors:
    print s
    for d in successors[s]:
        print " -- ", d
print "PREDECESSORS"
for p in predecessors:
    print p
    for d in predecessors[p]:
        print " -- ", d
'''

# Ensure that *all* subnets have entries in the table (prevents errors)
for subnet in subnets :
    if not successors.has_key(subnet) :
        successors[subnet] = Set([ ])
    if not predecessors.has_key(subnet) :
        predecessors[subnet] = Set([ ])

# Get dominators
dominators = findDominators()

print "\nImmediate dominators : "
for node in dominators.keys() : 
    print "   " + dominators[ node ] + " -> " + node
print 

# Reverse successor/predecessor tables, to get post-dominators


tempSuccessors = { }
tempPredecessors = { }

for subnet in subnets :
    tempSuccessors[subnet] = Set([ ])
    tempPredecessors[subnet] = Set([ ])

for node in successors.keys() :
    for succ in successors[node] :
        tempSuccessors[succ].add(node)
successors = tempSuccessors

for node in predecessors.keys() :
    for pred in predecessors[node] :
        tempPredecessors[pred].add(node)
predecessors = tempPredecessors

root = goal
postdominators = findDominators()

print "\nPost-dominators : "
for node in postdominators.keys() : 
    print "   " + postdominators[ node ] + " -> " + node
print

# Write dominance/postdominance results to file as Datalog tuples
fileHandle = open(outputFile, 'w')

for node in dominators.keys() :
    if dominators[node] != vroot: # don't record dominance by virtual root node
        fileHandle.write( "dominates( " + dominators[node] + ", " + node + " ).\n" )

for node in postdominators.keys() :
    if node != vroot: # don't record postdominance of virtual root node
        fileHandle.write( "postdominates( " + postdominators[node] + ", " + node + " ).\n" )

fileHandle.close()
