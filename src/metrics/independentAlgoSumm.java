/*
An implementation of the risk-assessment algorithm developed by Wang et al.
Author(s) : Su Zhang
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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
//import java.sql.ResultSet;
import java.sql.SQLException;
//import java.sql.Statement;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;


public class independentAlgoSumm {

	/**Input: An attack graph G with individual scores assigned to all vertices
Output: A set of cumulative scores for all vertices of G
Method:

3. While there exist unprocessed vertices
4. While there exists an unprocessed vertex v whose predecessors are all processed
5. Calculate P(v) and mark v as processed
6. For each vertex v in a cycle that has more than one incoming edge
7. Calculate P(v

) and mark v
 as processed
8. For each unprocessed vertex v
 in the cycles
9. Calculate P(v

) and mark v
 as processed
10. Return the set of all calculated cumulative scores @param args
	 */
	public static void main(String[] args) {

//nodes need to be stored at a hashtable with node id as the key and 
//an arraylist as its status including "type", status,  
		
		//unprocessed table includes nodes haven't been processed
		//the key is their ids and the value is an arraylist including
		//status, type (leaf, and, or), predecessors (another string arraylist)
		Hashtable<String, node> unprocessed = initializeNodes();

		
		//printArrayList((ArrayList<String>) unprocessed.get("2").get(3));
		
		//processed table includes nodes whose metrics have been calculated.
		//the key of the table is the node id and the value is its metric
		Hashtable<String, Float> processed = new Hashtable<String, Float> ();
		
		Hashtable<String, Float> conProb = constructConProb();
	//	System.out.println("initialization finished");
		//kernelAlgo is the kernel part of Wang's algorithm
		kernelAlgo(unprocessed, processed, conProb);
		
	}

	private static Hashtable<String, Float> constructConProb() {
		
		String line = "";
		
		int index = 0;
		
		//String cve = "";
		
		String ac = "";
		
		String node = "";
		
	//	String successor = "";
		
		//ArrayList<String> successors = new ArrayList<String>();
		
		float conProb = 0;
		
		Hashtable<String, Float>conProbTable = new Hashtable<String, Float>();
		
		//System.out.println("I am here");
		try{
			
			BufferedReader vertices= new BufferedReader(new FileReader("VERTICES.CSV"));

		while ((line = vertices.readLine()) != null) {
			//System.out.println(line);

			//if(line.contains("capability to likelihood")){
			
				//System.out.println("I am here");

				index = line.split(",").length;
				
				//find the id of the vulExist node
				node = line.split(",")[0];
				
				//search the metric over database
				ac = line.split(",")[index-1];
				
				//System.out.println(ac);
				
				conProb = Float.parseFloat(ac);
				
				//convert the letter metric into numeric value
				//conProb = convertLetter2Num(ac);
				
				//System.out.println("conProb is: "+ node +" : "+conProb);
				//for none-zeros, added them as conditional probabilities.
				if(!ac.trim().equals("0"))
					conProbTable.put(node, conProb);
		//	}
		
		}
		}
		
		catch(Exception e){
			
			e.printStackTrace();
		}
		
		//System.out.println("conProbTable's size is: "+ conProbTable.size());
		return conProbTable;
	}
/*
	//lookup ac value of cve from NVD database
	private static String lookup_ac(String cve) {

		String access = "";
		try{
			Connection con = getConnection();
			Statement sql = con.createStatement();
			//String query = "select access from nvd where id=\""+cve+"\"";
			String query = "select access from nvd where id=\""+cve+"\"";
			//System.out.println(query);
			ResultSet result = sql.executeQuery(query);
			result.next();
			access=result.getString(1);
			
		//	System.out.println("access is: "+access);
			
		}
		
		catch(Exception e){
			
			e.printStackTrace();
			
		}
		return access;
	}
*/
	public static Connection getConnection() throws SQLException,
	java.lang.ClassNotFoundException, IOException {

		Class.forName("com.mysql.jdbc.Driver");

		String url="";

		String userName="";
		
		String password="";
		
		File f = new File("config.txt");
		
		String path = f.getPath();
		
		BufferedReader breader= new BufferedReader(new FileReader(path));
		
		url=breader.readLine();
		
		userName=breader.readLine();
		
		password=breader.readLine();
		
		Connection con = DriverManager.getConnection(url, userName, password);
		
		return con;	


}
	
	//convert letter metric into numeric values
	/*
	private static float convertLetter2Num(String ac) {


		if(ac.equals("l"))
		
			return (float) 0.9;
		
		if(ac.equals("m"))
			
			return (float) 0.6;
			
		return (float)0.2;
	}
*/
	private static Hashtable<String, node> initializeNodes() {

		Hashtable<String, node> unprocessed = new Hashtable<String, node> ();
		
		Hashtable<String, ArrayList<String>> predecessorDict = new Hashtable<String, ArrayList<String>>();
		
		Hashtable<String, ArrayList<String>> successorDict = new Hashtable<String, ArrayList<String>>();

		String line = "";
		
		String id = "";
		
		String predeccesorID = "";
		
		String successorID = "";

		String type = "";
		
		ArrayList<String> predecessors = new ArrayList<String>();
		
		ArrayList<String> successors = new ArrayList<String>();

		
		try {
			BufferedReader arcs= new BufferedReader(new FileReader("ARCS.CSV"));
			
			//first step, collect all predecessors for each node
			arcs.mark(10000);
			
			//System.out.println(predecessorDict.get("14").size());

			while ((line = arcs.readLine()) != null) {
				
				//node here is the key
				id = line.split(",")[0];
				
				//System.out.println(node);
				//each precedent of the node
				predeccesorID = line.split(",")[1];
				
				//if the node already has a record in the dictionary
				if(predecessorDict.containsKey(id))
					
					//then take out the record
					predecessors = predecessorDict.get(id);
				
				else
					predecessors = new ArrayList<String>();
					
				//if the newly discovered precedent hasn't been 
				if(!predecessors.contains(predeccesorID))
					predecessors.add(predeccesorID);
					
				//put the record back with the newly discovered precedent
				predecessorDict.put(id, predecessors);
					
				
			}
			//System.out.println(node);
			//System.out.println(predecessorDict.get("14").size());

			
			arcs.reset();
			
			while ((line = arcs.readLine()) != null) {
				
				//node here is the key
				successorID = line.split(",")[0];
				
				//each precedent of the node
				id = line.split(",")[1];
				
				//empty the succesors at the begining of each iteration
				//successors =null;
				
				//if the node already has a record in the dictionary
				if(successorDict.containsKey(id))
					
					//then take out the record
					successors = successorDict.get(id);
				
				else
					
					successors= new ArrayList<String>();
					
				//if the newly discovered precedent hasn't been 
				if(!successors.contains(successorID))
					
					successors.add(successorID);
					
				//put the record back with the newly discovered precedent
				successorDict.put(id, successors);
				
			}
			
			//second step, collect all other information for each node,
			//including types status
			BufferedReader vertices= new BufferedReader(new FileReader("VERTICES.CSV"));
			
			while ((line = vertices.readLine()) != null) {
				
				//node here is the key
				id = line.split(",")[0];
				
				//type of the node
				type = line.split("\"")[3];
				
				//System.out.println("type is: "+type);
				
				node value = new node();
				value.status="UNPASSED";
				
				value.type= type;
				
				//default predecessors is an empty list.
				ArrayList<String> preds = new ArrayList<String>();
				
				value.predecessors=preds;
				
				//default successors is an empty list.
				ArrayList<String> succs = new ArrayList<String>();
				
				value.successors = succs;
				
				unprocessed.put(id, value);
				
			}
			//put predecessors into unprocessed list from predecessorsDict

			Set<String> keys = predecessorDict.keySet();
			
			int s = keys.size();
			
			String[] kys = keys.toArray(new String[s]);
		
			String key = "";

			for(int i=0; i< s; i++){
			
				key =kys[i];
				
				predecessors = predecessorDict.get(key);
				
				node value = new node();
				
				value=unprocessed.get(key);
			
				//update with a new predecessors
				value.predecessors= predecessors;
				
				unprocessed.put(key, value);
			
			}
		
		
			//put successors into unprocessed list from successorDict

			Set<String> suc_keys = successorDict.keySet();
	
			s = suc_keys.size();
			
			kys = suc_keys.toArray(new String[s]);
	
			for(int i=0; i< s; i++){
		
				key =kys[i];
				
				successors = successorDict.get(key);
				
				node value = new node();
				
				value=unprocessed.get(key);
		
				//update with a new predecessors
				value.successors = successors;
		
				unprocessed.put(key, value);
		
			}
	
		} catch (Exception e) {

			e.printStackTrace();
		}
		return unprocessed;
	}

	private static void kernelAlgo(Hashtable<String, node> unprocessed, Hashtable<String, Float> processed, Hashtable<String, Float> conProb) {

		Set<String> keys = unprocessed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";
		
		String type = "";

		//System.out.println(unprocessed.size());

		for(int i=0; i< s; i++){
		
			key =kys[i];
		
			//take the type of the node
			type = unprocessed.get(key).type;
			
			//System.out.println("type is: "+type);

			//1. For each initially satisfied condition c
			//2. Let P(c) = 1 and mark c as processed
			//for leaf nodes, just remove it from unprocessed and put them into processed
			if(type.contains("LEAF")){
				
				processed.put(key, (float) 1);
				
				unprocessed.remove(key);
			
			}
		}
		
		//System.out.println(unprocessed.size());

		
		String nodeWithAllPredecessorsProb = "";
	
		//While there exist unprocessed vertices
		while(!unprocessed.isEmpty()){
			
			//4. While there exists an unprocessed vertex v whose predecessors are all processed
		//	System.out.println("processed size is: "+processed.size());
		//	System.out.println("unprocessed size is: "+unprocessed.size());

			//	System.out.println(processed.containsKey(key));

			//System.out.println(existsUnprocessedWithAllPredecessorsProb(unprocessed, processed));
			while(existsUnprocessedWithAllPredecessorsProb(unprocessed, processed))
			
			{

				nodeWithAllPredecessorsProb = getANodeWithAllItsPredecessorsProb(unprocessed, processed);
	
				//System.out.println("nodeWithAllPredecessorsProb is: "+nodeWithAllPredecessorsProb);

				String node_type = (String) unprocessed.get(nodeWithAllPredecessorsProb).type;
		
				//System.out.println(node_type);
				//get predecessors of the node
				ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(nodeWithAllPredecessorsProb).predecessors;
		
				float metric = calculateMetric(nodeWithAllPredecessorsProb, node_type, predecessors, processed, conProb);
			
			//	if(nodeWithAllPredecessorsProb.equals("2"))
			//		System.out.println("2 has been passed");
				
				processed.put(nodeWithAllPredecessorsProb, metric);
			
				unprocessed.remove(nodeWithAllPredecessorsProb);
			
			}
			
		//	System.out.println("processed size is: "+processed.size());
		//	System.out.println("unprocessed size is: "+unprocessed.size());
			//line 6-7
			ArrayList<String> MultipleIncomingNodes = getMultipleIncomingNodes(unprocessed);

			Iterator <String> multiInNodesItr = MultipleIncomingNodes.iterator();
		
			//System.out.println("MultiIn-node size is: "+MultipleIncomingNodes.size());
			
			//System.out.println("MultiIn-node is: "+MultipleIncomingNodes.get(0));

			while(multiInNodesItr.hasNext()){
			
				String multiInNode = multiInNodesItr.next();
		
			
				//calculateMultiIncomNoedMetric() couldn't change global variables
				//System.out.println("before calculation processed size is: "+processed.size());
				//System.out.println("before calculation unprocessed size is: "+unprocessed.size());
				
				float multiIncomNodeMetric = calculateMultiIncomNodeMetric(multiInNode, processed, unprocessed, conProb);
				
				//System.out.println("after calculation processed size is: "+processed.size());
				//System.out.println("after calculation unprocessed size is: "+unprocessed.size());
				
				processed.put(multiInNode, multiIncomNodeMetric);
		
				unprocessed.remove(multiInNode);
		
			}
		//	System.out.println("processed size is: "+processed.size());
		//	System.out.println("unprocessed size is: "+unprocessed.size());
		//last part
			/*
			while(existsUnprocessedWithAllPredecessorsProb(unprocessed, processed))
			{
				nodeWithAllPredecessorsProb = getANodeWithAllItsPredecessorsProb(unprocessed, processed);
	
				String node_type = (String) unprocessed.get(nodeWithAllPredecessorsProb).get(0);
		
				//get predecessors of the node
				ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(nodeWithAllPredecessorsProb).get(2);
		
				float metric = calculateMetric(nodeWithAllPredecessorsProb, node_type, predecessors, processed);
			
				processed.put(nodeWithAllPredecessorsProb, metric);
			
				unprocessed.remove(nodeWithAllPredecessorsProb);
			
			}*/
			
			//printOutResults(processed);
		//	System.out.println(unprocessed.size());
		//	System.out.println(processed.size());

			//printOutUnprocessed(unprocessed);

		}
	//	printOutResults(processed);
		writeResultsIntoCSV(processed);
	}

	private static void writeResultsIntoCSV(Hashtable<String, Float> processed) {
		// TODO Auto-generated method stub
		
		String line = "";
		String node = "";
		int index = 0;
		float ac_flt = 0;
		
	/*	Runtime run = Runtime.getRuntime();
		Process pr;
		
		String src = "VERTICES_METRIC.CSV";
		String dst = "VERTICES.CSV";
		*/
		
try{
			
			BufferedReader vertices= new BufferedReader(new FileReader("VERTICES.CSV"));
		
			FileWriter fr = new FileWriter("VERTICES_METRICS.CSV");

		while ((line = vertices.readLine()) != null) {
			//System.out.println(line);

			//if(line.contains("capability to likelihood")){
			
				//System.out.println("I am here");

			  String elements[]= line.split(",");
			
				index = elements.length;
				//System.out.println("index is: "+index);
				
				//find the id of the vulExist node
				node = elements[0];
				//System.out.println("node is: "+node);
				
				ac_flt = processed.get(node);
				
				ac_flt = (float) (Math.round(ac_flt*10000.0)/10000.0);
				//System.out.println("ac is: "+ac_flt);
				
				//search the metric over database
				elements[index-1]= Float.toString(ac_flt);
			
				String newLine="";
				
			for(int i=0; i<index; i++){
				
				newLine=newLine+","+elements[i];
				
				//System.out.println(elements[i]);
			}
			
			//System.out.println(newLine);
			//int newLineLen = newLine.length();
			
			newLine = newLine.substring(1);
			
			//System.out.println(newLine);
			fr.write(newLine+"\n");
			
			
				
		}
		fr.close();
		
		//String src
		//String cmd = "mv "+src +" "+dst;
		//pr = run.exec(cmd);
		//pr.waitFor();
		
}
		
		catch(Exception e){
			
			e.printStackTrace();
			
		}
	}

	public static void printArrayList(ArrayList<String> ary){
		
		Iterator<String> ary_itr = ary.iterator();
		String element = "";
		while(ary_itr.hasNext()){
			
			element = ary_itr.next().toString();
			
			System.out.println(element);
		}
		
		
	}
	/*
	private static void printOutUnprocessed(
			Hashtable<String, ArrayList<node>> unprocessed) {

		Set<String> keys = unprocessed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";
		
		float metric = 0;

		for(int i=0; i< s; i++){
		
			key =kys[i];
			
			
			
			System.out.println(key);

		}		
	}
	*/
/*
	private static void printOutResults(Hashtable<String, Float> processed) {

		
		Set<String> keys = processed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";
		
		float metric = 0;

		for(int i=0; i< s; i++){
		
			key =kys[i];
			
			metric = processed.get(key);
			
			metric = (float) (Math.round(metric*10000.0)/10000.0);
			
			System.out.println(key+":	"+metric);

		}
		
	}
*/
	private static float calculateMultiIncomNodeMetric(
			String multiInNode, Hashtable<String, Float> processed_upper,
			Hashtable<String, node> unprocessed2, Hashtable<String, Float> conProb) {

		@SuppressWarnings("unchecked")
		Hashtable<String, node> unprocessed = (Hashtable<String, node>) unprocessed2.clone();
		
		@SuppressWarnings("unchecked")
		Hashtable<String, Float> processed = (Hashtable<String, Float>) processed_upper.clone();
		
		//ArrayList<String> successors = (ArrayList<String>) unprocessed.get(multiInNode).successors;
		
		String type = (String) unprocessed.get(multiInNode).type;
		
	//	System.out.println("pre-size is: "+unprocessed.get(multiInNode).size());

		unprocessed = removeOutgoings(unprocessed, multiInNode, type);
		
	//	System.out.println("post-size is: "+unprocessed.get(multiInNode).size());

		//System.out.println("after removal: "+unprocessed.containsKey(multiInNode));
		
		ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(multiInNode).predecessors;
		
		//one possible step could be added here: if predecessors are not in either processed 
		//or unprocessed, then it should be removed from predecessors.
		//System.out.println("multiInNode is: "+multiInNode);
		float metric =	calculateMetric(multiInNode, type, predecessors, processed, conProb);
		
		return metric;
	}

	private static Hashtable<String, node> removeOutgoings(
			Hashtable<String, node> unprocessed, String multiInNode, String type) {

	//	System.out.println("multiInNode is: "+multiInNode);
	//	System.out.println("unprocessed size is: "+unprocessed.size());
	//	printOutUnprocessed(unprocessed);
		//for AND nodes, we took out 
		ArrayList<String> successors = (ArrayList<String>) unprocessed.get(multiInNode).successors;
		
		Iterator <String> suc_itr = successors.iterator();
		
		String successor = "";
		
		if(type.contains("AND")){
		
			while(suc_itr.hasNext()){
				
				successor =	suc_itr.next().toString();
			
				//if the successor has been processed previously, then skip it.
				if(!unprocessed.containsKey(successor))
					continue;
				
				//obatain the predecessors of current successor
				ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(successor).predecessors;
				
				//if there is only one AND node leading to the next OR node, then
				//cut the OR node as well because the attack path will be disconnected also
				if(predecessors.size()==1){

					ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;

					unprocessed.remove(successor);	

					unprocessed = clearOrNode(succ_successors, unprocessed, multiInNode);	
					
					
				}
			
			}
			
		}
		
		if(type.contains("OR")){
			
			while(suc_itr.hasNext()){
				
				successor =	suc_itr.next().toString();

				//if the successor has been processed previously, then skip it.
				if(!unprocessed.containsKey(successor))
					continue;
				
				ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;

				unprocessed.remove(successor);	
			
				unprocessed = clearAndNode(succ_successors, unprocessed, multiInNode);	
				
				
			}
			
		}
		
		
		//remove all successors
		//System.out.println("real post-size is: "+unprocessed.get(multiInNode).size());

		if(unprocessed.containsKey(multiInNode)){
		
			ArrayList <String> new_succs = new ArrayList<String>();
		//	System.out.println("multiInNode status size is: "+unprocessed.size());
			
			unprocessed.get(multiInNode).successors = new_succs;
			//	unprocessed.put(multiInNode, (ArrayList) unprocessed.get(multiInNode).remove(3));
		}	
		return unprocessed;
	}

	private static Hashtable<String, node> clearOrNode(ArrayList<String> successors,
			Hashtable<String, node> unprocessed, String head) {

		//head here refers to the entry point of the loop
		//ArrayList<String> successors = (ArrayList<String>) unprocessed.get(node).get(3);
		
		Iterator <String> suc_itr = successors.iterator();
		
		String successor = "";
		
		while(suc_itr.hasNext()){
			
			successor =	suc_itr.next().toString();
		
			//if current successor has been deleted previously, Or it loops back to the beginning point then skip it.
			if(!unprocessed.containsKey(successor)||successor.equals(head))
				continue;
			
			ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;
			
			unprocessed.remove(successor);
			
			unprocessed = clearAndNode(succ_successors, unprocessed, head);	
			
				
		
		}
		
		return unprocessed;
		
	}

	private static Hashtable<String, node> clearAndNode(ArrayList<String> successors,
			Hashtable<String, node> unprocessed, String head) {
		
		//ArrayList<String> successors = (ArrayList<String>) unprocessed.get(node).get(3);
		
		Iterator <String> suc_itr = successors.iterator();
		
		String successor = "";
		
		while(suc_itr.hasNext()){
			
			successor =	suc_itr.next().toString();
			
			//if current successor has been deleted previously, Or loops back to the beginning point, then skip it.
			if(!unprocessed.containsKey(successor)||successor.equals(head))
				continue;
			//obatain the predecessors of current successor
			ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(successor).predecessors;
			
			//if there is only one AND node leading to the next OR node, then
			//cut the OR node as well because the attack path will be disconnected also
			if(predecessors.size()==1){
			
				ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;

				unprocessed.remove(successor);	
				
				clearOrNode(succ_successors, unprocessed, head);	
				
				
			}
		
		}
	
		return unprocessed;
		
	}

	private static ArrayList<String> getMultipleIncomingNodes(
			Hashtable<String, node> unprocessed) {

		Set<String> keys = unprocessed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";

		ArrayList <String> MultipleIncomingNodes = new ArrayList<String>(); 
		
		ArrayList<String> preds = new ArrayList<String>();
		
		//System.out.println(unprocessed.get("2").get(2));
		
		for(int i=0; i< s; i++){
			
			key = kys[i];
			
			preds = (ArrayList<String>) unprocessed.get(key).predecessors;
			
			//if multiple incoming nodes
			if(preds.size()>1)
			
				MultipleIncomingNodes.add(key);
			
		}
		
		return MultipleIncomingNodes;
	}

	private static float calculateMetric(String nodeWithAllPredecessorsProb,
			String node_type, ArrayList<String> predecessors, Hashtable<String, Float> processed, Hashtable<String, Float> conProb) {

	//	System.out.println("nodeWithAllPredecessorsProb is: "+nodeWithAllPredecessorsProb);
		
		if(node_type.contains("AND"))
		
			return calculateANDMetrics(nodeWithAllPredecessorsProb, predecessors, processed, conProb);
		
		return calculateORMetrics(predecessors, processed);
	}

	private static float calculateORMetrics(ArrayList<String> predecessors,
			Hashtable<String, Float> processed) {

		
		float cumm_metric = 1;
		
		float metric = 1;
		
		
		
		String predecessor = "";
		
		Iterator<String> pred_itr = predecessors.iterator();
		
		while(pred_itr.hasNext()){
			
			predecessor = pred_itr.next().toString();

			//if one predecessor has been deleted previously through 
			//de-cycling, then skip it as if it wasn't a predecessor of
			//current node.
			if(!processed.containsKey(predecessor))
				continue;
		//	System.out.println(predecessor);
			//get metric of each predecessor
			metric = processed.get(predecessor);
			
			//multiply metircs altogether
			cumm_metric = cumm_metric*(1-metric);
			
		}

		cumm_metric = 1 -cumm_metric;
		
		return cumm_metric;
	
	}

	private static float calculateANDMetrics(String node, ArrayList<String> predecessors,
			Hashtable<String, Float> processed, Hashtable<String, Float> conProb) {

		float cumm_metric = 1;
		
		float metric = 1;
	
		float con_metric = 1;
		
		String predecessor = "";
		
		Iterator <String>pred_itr = predecessors.iterator();
		
		while(pred_itr.hasNext()){
			
			predecessor = pred_itr.next().toString();
			
			//get metric of each predecessor
			if(!processed.containsKey(predecessor))
				continue;
			
			metric = processed.get(predecessor);
			
			//multiply metircs altogether
			cumm_metric = cumm_metric*metric;
			
		}
		
		//for all other AND nodes other than exploitation, the conditional 
		//probabilities are all 0.8. If 
		if(conProb.containsKey(node)){
			
			con_metric = conProb.get(node);
		}
		else
		{	
		//	System.out.println(node);
			con_metric = (float) 0.8;
		}	
		//return the cumulative probability times conditional probability
		return cumm_metric*con_metric;
	
	}

	private static String getANodeWithAllItsPredecessorsProb(
			Hashtable<String, node> unprocessed, Hashtable<String, Float> processed) {
	
		Set<String> keys = unprocessed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";
		
		String predecessor = "";

		for(int i=0; i< s; i++){
			
			key =kys[i];
			
			ArrayList<String> predecessors = new ArrayList<String>();
			
			
			predecessors = (ArrayList<String>) unprocessed.get(key).predecessors;
	
			Iterator <String>preds_itr = predecessors.iterator();
			//System.out.println("node is: "+key);
			//System.out.println("predecessors' size is: "+predecessors.size());
			//we define a counter to detect how many 
			int counter = 0;
			
			while(preds_itr.hasNext()){
				
				predecessor = preds_itr.next().toString();
				
				//System.out.println(key);
			//	System.out.println(predecessor);
			//	System.out.println(processed.containsKey("6"));
				if(!processed.containsKey(predecessor))
				
					break;
			
				counter++;
			}
				
		//	System.out.println("counter is: "+ counter);
			
			if(predecessors.size()==counter){
				
			//	System.out.println("node is: "+key);
			//	System.out.println("predecessors.size() is: "+ predecessors.size());
				return key;
				
			}
		
		}
		
		return null;
		
	}

	private static boolean existsUnprocessedWithAllPredecessorsProb(
			Hashtable<String, node> unprocessed, Hashtable<String, Float> processed) {

		Set<String> keys = unprocessed.keySet();
		
		int s = keys.size();
		
		String[] kys = keys.toArray(new String[s]);
		
		String key = "";
		
		String predecessor = "";

		for(int i=0; i< s; i++){
			
			key =kys[i];
			
			ArrayList<String> predecessors = new ArrayList<String>();
			
			predecessors = (ArrayList<String>) unprocessed.get(key).predecessors;
	
			Iterator <String>value_itr = predecessors.iterator();
			
		//	System.out.println("predecessor size is: "+ predecessors.size());	
			
		//	System.out.println("key is: "+ key);

			//we define a counter to detect how many 
			int counter = 0;
			
			while(value_itr.hasNext()){
				
				predecessor = value_itr.next().toString();
			
				//System.out.println(predecessor);	
				
				if(!processed.containsKey(predecessor)){
				
					break;
					
				}
				
				counter++;
				
			}
			
			//System.out.println(predecessors.size());	
			//System.out.println(counter);	

			if(predecessors.size()==counter){
					
				return true;
			
			
			}
		}
		
		return false;
	
	}

}
