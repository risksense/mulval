/*
Create a database storing the NVD data
Author(s) : Su Zhang, Xinming Ou
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

import java.sql.*;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.dom4j.io.XMLWriter;

public class InitializeDB {

	public static Connection getConnection() throws SQLException,
	  java.lang.ClassNotFoundException, IOException {
		Class.forName("com.mysql.jdbc.Driver");
		String url = "";
		String userName = "";
		String password = "";
		String MulvalRootEnv = System.getenv("MULVALROOT");
		File f = new File("config.txt");
		String path = f.getPath();
		BufferedReader breader = new BufferedReader(new FileReader(path));
		url = breader.readLine();
		userName = breader.readLine();
		password = breader.readLine();
		Connection con = DriverManager.getConnection(url, userName, password);
		breader.close();
		return con;	
	}

	public static void main(String[] args) {
		setupDB(Integer.parseInt(args[0]));
	}

	public static void setupDB(int year) {
		try {
			Connection con = getConnection();
			Statement sql = con.createStatement();
			sql.execute("drop table if exists nvd");                                                                                                                                                                                                        //,primary key(id)
			sql.execute("create table nvd(id varchar(20) not null,soft varchar(160) not null default 'ndefined',rng varchar(100) not null default 'undefined',lose_types varchar(100) not null default 'undefind',severity varchar(20) not null default 'unefined',access varchar(20) not null default 'unefined');");
			SAXReader saxReader = new SAXReader();
			for(int ct = 2002; ct <= year; ct++) {
				String fname="nvd_xml_files/nvdcve-"+Integer.toString(ct)+".xml";
				Document document = saxReader.read(fname);
				List entry = document.selectNodes("/*[local-name(.)='nvd']/*[local-name(.)='entry']");
				Iterator ent = entry.iterator();
	            int act=0;
				while (ent.hasNext()) {
					Element id = (Element) ent.next();
					String cveid = id.attributeValue("name");
					String cvss = "";
					String access = "";
					String sev = "";
					String host = "localhost";
					String sftw = "";
					String rge = "";
					String rge_tmp = "";
					String lose_tmp = "";
					String lose_types = "";
					ArrayList<String> subele = new ArrayList<String>();
					ArrayList<String> attr = new ArrayList<String>();
					Iterator ei = id.elementIterator();
					while (ei.hasNext()) { // put all of the subelements' names(subelement of entry) to the array list
						Element sube = (Element) ei.next();
						subele.add(sube.getName());
					}
					Iterator i = id.attributeIterator();
					while (i.hasNext()) { // put the attributes of the entries to the arraylist
						Attribute att = (Attribute) i.next();
						attr.add(att.getName());
					}
					if (subele.contains("vuln_soft")) {
						Element vs = (Element) id.element("vuln_soft");
						Iterator itr = vs.elementIterator("prod");
						while (itr.hasNext()) { // record all of the softwares
							Element n = (Element) itr.next();
							sftw = n.attributeValue("name");
							if(sftw.contains("'")) {
								sftw=sftw.replace("'", "''");
							}
							break;
						}
					}
					if (attr.contains("severity")) {
						sev = id.attributeValue("severity");
					}
					if (attr.contains("CVSS_vector")) {
						cvss = id.attributeValue("CVSS_vector");
						char ac = cvss.charAt(9);
						if (ac == 'L')
							access = "l";
						else if (ac == 'M')
							access = "m";
						else if (ac == 'H')
							access = "h";
						else ;
					}
					if (subele.contains("range")) { // to get the range as a array
						Element vs = (Element) id.element("range");
						Iterator rgi = vs.elementIterator();
						while (rgi.hasNext()) { // record all of the softwares
							Element rg = (Element) rgi.next();
							if (rg.getName().equals("user_init"))
								rge_tmp = "user_action_req";
							else if (rg.getName().equals("local_network"))
								rge_tmp = "lan";
							else if (rg.getName().equals("network"))
								rge_tmp = "remoteExploit";
							else if (rg.getName().equals("local"))
								rge_tmp = "local";
							else
								rge_tmp = "other";
							rge = rge + "''"+rge_tmp + "'',";
						}
						int lr = rge.length();
						rge = rge.substring(0, lr - 1);// delete the last comma
					}
					if (subele.contains("loss_types")) {
						Element lt = (Element) id.element("loss_types");
						Iterator lti = lt.elementIterator();
						while (lti.hasNext()) {
							ArrayList<String> isecat = new ArrayList<String>();
							Element ls = (Element) lti.next();
							if (ls.getName().equals("avail"))
								lose_tmp = "availability_loss";
							else if (ls.getName().equals("conf"))
								lose_tmp = "data_loss";
							else if (ls.getName().equals("int"))
								lose_tmp = "data_modification";
							else
								lose_tmp = "other";
							lose_types = lose_types +"''"+ lose_tmp + "'',";
						}
						int ltp = lose_types.length();
						lose_types = lose_types.substring(0, ltp - 1);// delete the last comma
					}
					String insert = "insert nvd values('" + cveid + "','"
							+ sftw + "','" + rge + "','" + lose_types + "','" + sev
							+ "','" + access+"')";
					sql.execute(insert);
				}
			}
			sql.close();
			con.close();
		} catch (java.lang.ClassNotFoundException e) {
			System.err.println("ClassNotFoundException:" + e.getMessage());
		} catch (SQLException ex) {
			System.err.println("SQLException:" + ex.getMessage());
		} catch (DocumentException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void clearEntryWithVulsoft(String filename) {
		try {
			SAXReader saxReader = new SAXReader();
			Document document = saxReader.read(filename);
			List soft = document
					.selectNodes("/*[local-name(.)='nvd']/*[local-name(.)='entry']/*[local-name(.)='vuln_soft']");
			Iterator sft = soft.iterator(); 
			Element nvd = (Element) document
					.selectSingleNode("/*[local-name(.)='nvd']");
			while (sft.hasNext()) {
				Element vsft = (Element) sft.next();
				nvd.remove(vsft.getParent());
				XMLWriter output = new XMLWriter(new FileWriter(filename));//
				output.write(document);
				output.flush();
				output.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
