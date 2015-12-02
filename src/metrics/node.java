/*
 * Node is the node included in each attack graph.
 * 
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

import java.util.ArrayList;

public class node {
	public String id = ""; //node number
	public String status = ""; //PASSED or UNPASSED
	public String type = ""; //AND, OR and LEAF
	//A set of predecessors of the current node.
	public ArrayList<String> predecessors = new ArrayList<String>();
	// A set of successors of the current node.
	public ArrayList<String> successors = new ArrayList<String>();
	// Metric for each node
	public float metric = 0; 
}
