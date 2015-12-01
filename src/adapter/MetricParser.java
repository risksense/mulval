/*
Put appropriate metrics to the nodes for further calculations.
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
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Set;


public class MetricParser {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		File f = new File("assessed.P");
		File f1 = new File("VERTICES.CSV");
		String path = f.getPath();
		String path1 = f1.getPath();
		String l="";
		String l2="";
		String tmp="";
		String s1 = "";
		//String s2 = "";
		//ArrayList<ArrayList> vert = new ArrayList<ArrayList>();
		int m = 0;
		Hashtable<String, ArrayList<String>> hs= new Hashtable<String, ArrayList<String>>();
		ArrayList<String []> ls = new ArrayList <String[]> ();
		//String [] tp1;
		String [] tp;
		try{
			BufferedReader breader= new BufferedReader(new FileReader(path));	
			while (( l = breader.readLine()) != null) {
				if(l.contains("OR-nodes"))
				{
					
					while((!((tmp = breader.readLine()).length()==0))&&isParsableToInt(tmp.substring(0, 1))){
						
						tp = tmp.split(":");
						ls.add(tp);
						
					}
				}
				if(l.contains("AND-nodes"))
					break;
			}
			BufferedReader br= new BufferedReader(new FileReader(path1));	
			while (( l2 = br.readLine()) != null) {
			   m=l2.indexOf(",");
			   ArrayList <String> al = new ArrayList<String>();
			   s1=l2.substring(0, m); //KEY
			   //s2=l2.substring(m);
			   al.add(l2);
			   hs.put(s1, al);
				
			}
			int len=ls.size();
			for(int i=0; i<len;i++){
				if (hs.containsKey(ls.get(i)[0]))
				{ 
					
					ArrayList <String>arr = hs.get(ls.get(i)[0]);
					String a = arr.get(0);
					int w=a.length();
					String b = a.substring(0, w-2);
					arr.remove(0);
					arr.add(b+",");
					arr.add(ls.get(i)[1].trim());
					hs.put(ls.get(i)[0], arr); }
				
			}
			
			 FileWriter fr = new FileWriter("riskassessment.txt");
			// int lt = hs.size();
			 Set<String> keys = hs.keySet();
			 int s = keys.size();
             String []kys = keys.toArray(new String[s]);
			 for(int n=0; n< s; n++){
				 String sk = "";
				 ArrayList<String>item = hs.get(kys[n]);
				 int lm = item.size();
				 for(int y=0; y<lm; y++){
					 
					 sk= sk +item.get(y);
				 }
				 fr.write(sk+"\n");
			 }
			 fr.close();
		}
		
		catch(Exception e){
			
			e.printStackTrace();
		}
		
	}
	public static boolean isParsableToInt(String i)
	{
	try
	{
	Integer.parseInt(i);
	return true;
	}
	catch(NumberFormatException nfe)
	{
	return false;
	}
	}

}
