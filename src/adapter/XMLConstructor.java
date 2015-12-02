/*
Output an XML format of MulVAL attack-graph
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
import java.io.FileReader;
import java.io.FileWriter;

public class XMLConstructor {

	public static void main(String[] args) {
		constructXML();
	}

	private static void constructXML() {
		String node1 ="";
		String node2 = "";
		String line = "";
		String id = "";
		String fact = "";
		String type = "";
		String metric="";
		String line_items [];
		int line_len = 0;
		try {
			FileWriter fr = new FileWriter("AttackGraph.xml");
			BufferedReader arcs = new BufferedReader(new FileReader("ARCS.CSV"));
			fr.write("<attack_graph>\n");
			fr.write("<arcs>\n");
			// Collect all predecessors for each node
			while ((line = arcs.readLine()) != null) {
				fr.write("<arc>\n");
				// Node here is the key
				node1 = line.split(",")[0];
				node2 = line.split(",")[1];
				fr.write("<src>"+node1+"</src>\n");
				fr.write("<dst>"+node2+"</dst>\n");
				fr.write("</arc>\n");
			}
			arcs.close();
			fr.write("</arcs>\n");
			BufferedReader vertices = new BufferedReader(new FileReader("VERTICES.CSV"));
			fr.write("<vertices>\n");
			while ((line = vertices.readLine()) != null) {
				id = line.split(",")[0];
				fact = line.split("\"")[1];
				type = line.split("\"")[3];
				line_items = line.split(",");
				line_len = line_items.length;
				metric = line_items[line_len-1];
				fr.write("<vertex>\n");
				fr.write("<id>"+id+"</id>\n");
				fr.write("<fact>"+fact+"</fact>\n");
				fr.write("<metric>"+metric+"</metric>\n");
				fr.write("<type>"+type+"</type>\n");
				fr.write("</vertex>\n");
			}
			fr.write("</vertices>\n");
			vertices.close();
			fr.write("</attack_graph>\n");
			fr.close();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
