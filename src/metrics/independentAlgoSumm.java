/*
 * An implementation of the risk-assessment algorithm developed by Wang et al.
 * Author(s) : Su Zhang
 * Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;

public class independentAlgoSumm {
	/**
	 * Input: An attack graph G with individual scores assigned to all vertices
	 * Output: A set of cumulative scores for all vertices of G
	 * Method:
	 * 3. While there exist unprocessed vertices
	 * 4. While there exists an unprocessed vertex v whose predecessors are all processed
	 * 5. Calculate P(v) and mark v as processed
	 * 6. For each vertex v in a cycle that has more than one incoming edge
	 * 7. Calculate P(v) and mark v as processed
	 * 8. For each unprocessed vertex v in the cycles
	 * 9. Calculate P(v) and mark v as processed
	 * 10. Return the set of all calculated cumulative scores
	 */
	public static void main(String[] args) {
		/* Nodes need to be stored at a hashtable with node id as the key and 
		 * an arraylist as its status including "type", status,  
		 * unprocessed table includes nodes haven't been processed
		 * the key is their ids and the value is an arraylist including
		 * status, type (leaf, and, or), predecessors (another string arraylist)
		 */
		Hashtable<String, node> unprocessed = initializeNodes();
		/* Processed table includes nodes whose metrics have been calculated.
		 * the key of the table is the node id and the value is its metric
		 */
		Hashtable<String, Float> processed = new Hashtable<String, Float> ();
		Hashtable<String, Float> conProb = constructConProb();
		// kernelAlgo is the kernel part of Wang's algorithm
		kernelAlgo(unprocessed, processed, conProb);
	}

	private static Hashtable<String, Float> constructConProb() {
		String line = "", ac = "", node = "";;
		int index = 0;
		float conProb = 0;
		Hashtable<String, Float>conProbTable = new Hashtable<String, Float>();
		try {
			BufferedReader vertices= new BufferedReader(new FileReader("VERTICES.CSV"));
			while ((line = vertices.readLine()) != null) {
					index = line.split(",").length;
					// Find the id of the vulExist node
					node = line.split(",")[0];
					// Search the metric over database
					ac = line.split(",")[index-1];
					conProb = Float.parseFloat(ac);
					// Convert the letter metric into numeric value
					// conProb = convertLetter2Num(ac);
					// For none-zeros, added them as conditional probabilities.
					if(!ac.trim().equals("0"))
						conProbTable.put(node, conProb);
			}
			vertices.close();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return conProbTable;
	}

	public static Connection getConnection() throws SQLException,
	java.lang.ClassNotFoundException, IOException {
		Class.forName("com.mysql.jdbc.Driver");
		String url = "";
		String userName = "";
		String password = "";
		File f = new File("config.txt");
		String path = f.getPath();
		BufferedReader breader = new BufferedReader(new FileReader(path));
		url = breader.readLine();
		userName = breader.readLine();
		password = breader.readLine();
		breader.close();
		Connection con = DriverManager.getConnection(url, userName, password);
		return con;	
	}
	
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
			// Collect all predecessors for each node
			arcs.mark(10000);
			while ((line = arcs.readLine()) != null) {
				// Node here is the key
				id = line.split(",")[0];
				// Each precedent of the node
				predeccesorID = line.split(",")[1];
				// If the node already has a record in the dictionary
				if(predecessorDict.containsKey(id)) // take out the record
					predecessors = predecessorDict.get(id);
				else
					predecessors = new ArrayList<String>();
				//if the newly discovered precedent hasn't been 
				if(!predecessors.contains(predeccesorID))
					predecessors.add(predeccesorID);
				//put the record back with the newly discovered precedent
				predecessorDict.put(id, predecessors);
			}
			arcs.reset();
			while ((line = arcs.readLine()) != null) {
				//node here is the key
				successorID = line.split(",")[0];
				// Each precedent of the node
				id = line.split(",")[1];
				// Empty the successors at the beginning of each iteration
				// successors = null;
				// If the node already has a record in the dictionary
				if(successorDict.containsKey(id)) // take out the record
					successors = successorDict.get(id);
				else
					successors= new ArrayList<String>();
				if(!successors.contains(successorID))
					successors.add(successorID);
				// Put the record back with the newly discovered precedent
				successorDict.put(id, successors);
			}
			arcs.close();
			// Second step, collect all other information for each node, including types status
			BufferedReader vertices = new BufferedReader(new FileReader("VERTICES.CSV"));
			while ((line = vertices.readLine()) != null) {
				// Node here is the key
				id = line.split(",")[0];
				// Type of the node
				type = line.split("\"")[3];
				node value = new node();
				value.status="UNPASSED";
				value.type= type;
				// Default predecessors is an empty list.
				ArrayList<String> preds = new ArrayList<String>();
				value.predecessors=preds;
				// Default successors is an empty list.
				ArrayList<String> succs = new ArrayList<String>();
				value.successors = succs;
				unprocessed.put(id, value);
			}
			vertices.close();
			// Put predecessors into unprocessed list from predecessorsDict
			Set<String> keys = predecessorDict.keySet();
			int s = keys.size();
			String[] kys = keys.toArray(new String[s]);
			String key = "";
			for(int i = 0; i< s; i++) {
				key = kys[i];
				predecessors = predecessorDict.get(key);
				node value = new node();
				value = unprocessed.get(key);
				//update with a new predecessors
				value.predecessors = predecessors;
				unprocessed.put(key, value);
			}
			// Put successors into unprocessed list from successorDict
			Set<String> suc_keys = successorDict.keySet();
			s = suc_keys.size();
			kys = suc_keys.toArray(new String[s]);
			for(int i = 0; i < s; i++) {
				key = kys[i];
				successors = successorDict.get(key);
				node value = new node();
				value = unprocessed.get(key);
				// Update with a new predecessors
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
		String key = "", type = "", nodeWithAllPredecessorsProb = "";;
		for(int i = 0; i < s; i++) {
			key = kys[i];
			// Take the type of the node
			type = unprocessed.get(key).type;
			//1. For each initially satisfied condition c
			//2. Let P(c) = 1 and mark c as processed
			// For leaf nodes, just remove it from unprocessed and put them into processed
			if(type.contains("LEAF")) {
				processed.put(key, (float) 1);
				unprocessed.remove(key);
			}
		}
		// While there exist unprocessed vertices
		while(!unprocessed.isEmpty()) {
			// 4. While there exists an unprocessed vertex v whose predecessors are all processed
			while(existsUnprocessedWithAllPredecessorsProb(unprocessed, processed)) {
				nodeWithAllPredecessorsProb = getANodeWithAllItsPredecessorsProb(unprocessed, processed);
				String node_type = (String) unprocessed.get(nodeWithAllPredecessorsProb).type;
				// Get predecessors of the node
				ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(nodeWithAllPredecessorsProb).predecessors;
				float metric = calculateMetric(nodeWithAllPredecessorsProb, node_type, predecessors, processed, conProb);
				processed.put(nodeWithAllPredecessorsProb, metric);
				unprocessed.remove(nodeWithAllPredecessorsProb);
			}
			// Line 6-7
			ArrayList<String> MultipleIncomingNodes = getMultipleIncomingNodes(unprocessed);
			Iterator <String> multiInNodesItr = MultipleIncomingNodes.iterator();
			while(multiInNodesItr.hasNext()) {
				String multiInNode = multiInNodesItr.next();
				//calculateMultiIncomNoedMetric() couldn't change global variables
				float multiIncomNodeMetric = calculateMultiIncomNodeMetric(multiInNode, processed, unprocessed, conProb);
				processed.put(multiInNode, multiIncomNodeMetric);
				unprocessed.remove(multiInNode);
			}
		}
		writeResultsIntoCSV(processed);
	}

	private static void writeResultsIntoCSV(Hashtable<String, Float> processed) {
		String line = "", node = "";
		int index = 0;
		float ac_flt = 0;
		try {
			BufferedReader vertices= new BufferedReader(new FileReader("VERTICES.CSV"));
			FileWriter fr = new FileWriter("VERTICES_METRICS.CSV");
			while ((line = vertices.readLine()) != null) {
				  String elements[] = line.split(",");
					index = elements.length;
					// Find the id of the vulExist node
					node = elements[0];
					ac_flt = processed.get(node);
					ac_flt = (float) (Math.round(ac_flt*10000.0)/10000.0);
					// Search the metric over database
					elements[index-1] = Float.toString(ac_flt);
					String newLine = "";
				for(int i = 0; i < index; i++) {
					newLine = newLine + "," + elements[i];
				}
				newLine = newLine.substring(1);
				fr.write(newLine+"\n");
			}
			vertices.close();
			fr.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public static void printArrayList(ArrayList<String> ary) {
		Iterator<String> ary_itr = ary.iterator();
		String element = "";
		while(ary_itr.hasNext()) {
			element = ary_itr.next().toString();
			System.out.println(element);
		}
	}

	private static float calculateMultiIncomNodeMetric(
			String multiInNode, Hashtable<String, Float> processed_upper,
			Hashtable<String, node> unprocessed2, Hashtable<String, Float> conProb) {
		@SuppressWarnings("unchecked")
		Hashtable<String, node> unprocessed = (Hashtable<String, node>) unprocessed2.clone();
		@SuppressWarnings("unchecked")
		Hashtable<String, Float> processed = (Hashtable<String, Float>) processed_upper.clone();
		String type = (String) unprocessed.get(multiInNode).type;
		unprocessed = removeOutgoings(unprocessed, multiInNode, type);
		ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(multiInNode).predecessors;
		/* One possible step could be added here: if predecessors are not in
		 * either processed or unprocessed, then it should be removed from
		 * predecessors.
		 */
		float metric =	calculateMetric(multiInNode, type, predecessors, processed, conProb);
		return metric;
	}

	private static Hashtable<String, node> removeOutgoings(
	Hashtable<String, node> unprocessed, String multiInNode, String type) {
		ArrayList<String> successors = (ArrayList<String>) unprocessed.get(multiInNode).successors;
		Iterator <String> suc_itr = successors.iterator();
		String successor = "";
		if(type.contains("AND")) {
			while(suc_itr.hasNext()) {
				successor =	suc_itr.next().toString();
				// If the successor has been processed previously, then skip it.
				if(!unprocessed.containsKey(successor))
					continue;
				// Obtain the predecessors of current successor
				ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(successor).predecessors;
				/* If there is only one AND node leading to the next OR node,
				 * then cut the OR node as well because the attack path will be
				 * disconnected also.
				 */
				if(predecessors.size() == 1) {
					ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;
					unprocessed.remove(successor);	
					unprocessed = clearOrNode(succ_successors, unprocessed, multiInNode);	
				}
			}
		}
		
		if(type.contains("OR")) {
			while(suc_itr.hasNext()) {
				successor =	suc_itr.next().toString();
				// If the successor has been processed previously, then skip it.
				if(!unprocessed.containsKey(successor))
					continue;
				ArrayList<String> succ_successors = (ArrayList<String>) unprocessed.get(successor).successors;
				unprocessed.remove(successor);	
				unprocessed = clearAndNode(succ_successors, unprocessed, multiInNode);	
			}
		}
		// Remove all successors
		if(unprocessed.containsKey(multiInNode)){
			ArrayList <String> new_succs = new ArrayList<String>();
			unprocessed.get(multiInNode).successors = new_succs;
		}	
		return unprocessed;
	}

	private static Hashtable<String, node> clearOrNode(ArrayList<String> successors,
			Hashtable<String, node> unprocessed, String head) {
		// Head here refers to the entry point of the loop
		Iterator <String> suc_itr = successors.iterator();
		String successor = "";
		while(suc_itr.hasNext()) {
			successor =	suc_itr.next().toString();
			/* If current successor has been deleted previously, Or it loops
			 * back to the beginning point then skip it.
			 */
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
		Iterator <String> suc_itr = successors.iterator();
		String successor = "";
		while(suc_itr.hasNext()) {
			successor =	suc_itr.next().toString();
			/* If current successor has been deleted previously, Or loops
			 * back to the beginning point, then skip it.
			 */
			if(!unprocessed.containsKey(successor) || successor.equals(head))
				continue;
			// Obtain the predecessors of current successor
			ArrayList<String> predecessors = (ArrayList<String>) unprocessed.get(successor).predecessors;
			/* If there is only one AND node leading to the next OR node,
			 * then cut the OR node as well because the attack path will be
			 * disconnected also.
			 */
			if(predecessors.size() == 1) {
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
		for(int i = 0; i < s; i++) {
			key = kys[i];
			preds = (ArrayList<String>) unprocessed.get(key).predecessors;
			// If multiple incoming nodes
			if(preds.size() > 1)
				MultipleIncomingNodes.add(key);
		}
		return MultipleIncomingNodes;
	}

	private static float calculateMetric(String nodeWithAllPredecessorsProb,
										 String node_type,
										 ArrayList<String> predecessors,
										 Hashtable<String, Float> processed,
										 Hashtable<String, Float> conProb) {
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
		while(pred_itr.hasNext()) {
			predecessor = pred_itr.next().toString();
			/* If one predecessor has been deleted previously through de-cycling,
			 * then skip it as if it wasn't a predecessor of current node.
			 */
			if(!processed.containsKey(predecessor))
				continue;
			// Get metric of each predecessor
			metric = processed.get(predecessor);
			// Multiply metircs altogether
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
		while(pred_itr.hasNext()) {
			predecessor = pred_itr.next().toString();
			//Get metric of each predecessor
			if(!processed.containsKey(predecessor))
				continue;
			metric = processed.get(predecessor);
			// Multiply metrics altogether
			cumm_metric = cumm_metric*metric;
		}
		
		// For all other AND nodes other than exploitation, the conditional probabilities are all 0.8. If 
		if(conProb.containsKey(node)) {
			con_metric = conProb.get(node);
		}
		else {
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
		for(int i = 0; i < s; i++) {
			key = kys[i];
			ArrayList<String> predecessors = new ArrayList<String>();
			predecessors = (ArrayList<String>) unprocessed.get(key).predecessors;
			Iterator <String>preds_itr = predecessors.iterator();
			// Define a counter to detect how many 
			int counter = 0;
			while(preds_itr.hasNext()){
				predecessor = preds_itr.next().toString();
				if(!processed.containsKey(predecessor))
					break;
				counter++;
			}
			if(predecessors.size() == counter){
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
		for(int i = 0; i < s; i++) {
			key = kys[i];
			ArrayList<String> predecessors = new ArrayList<String>();
			predecessors = (ArrayList<String>) unprocessed.get(key).predecessors;
			Iterator <String>value_itr = predecessors.iterator();
			// Define a counter to detect how many 
			int counter = 0;
			while(value_itr.hasNext()) {
				predecessor = value_itr.next().toString();
				if(!processed.containsKey(predecessor)) {
					break;
				}
				counter++;
			}
			if(predecessors.size() == counter){
				return true;
			}
		}
		return false;
	}
}
