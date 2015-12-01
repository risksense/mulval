/*
Retrieve reletive data from NVD database for further calculation.
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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;


public class GetTplQry {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
String filename=args[0];
File f = new File(filename);
String path = f.getPath();
String cvdid="";
String hostname="";
try{
	
	BufferedReader breader= new BufferedReader(new FileReader(path));
	ArrayList<String> cve= new ArrayList<String>();
	hostname=breader.readLine();
	while ((cvdid = breader.readLine()) != null) {
		
		cve.add(cvdid); //put all of the cve ids into the arrayList
		
	}
	writeTpls(cve,hostname);
	writeAccount(hostname);
}

catch(Exception e){
	
	e.printStackTrace();
}
	}
	public static Connection getConnection() throws SQLException,
	java.lang.ClassNotFoundException, IOException {
//String url = "jdbc:mysql://localhost:3306/mulvalDB";
//String url = "jdbc:mysql://mysql.cis.ksu.edu:3306/zhangs84";
//String password="8CFQZZyF";
Class.forName("com.mysql.jdbc.Driver");
//String userName = "root";
//String password = "";
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
    public static void writeAccount(String hostname){
    	
    	
    	
    	try{
    		
    		FileWriter fr= new FileWriter("accountinfo.P");
            fr.write("inCompetent(victim).\n");
            fr.write("hasAccount(victim, '"+hostname+"', user).\n");
	    fr.write("hacl("+hostname+", internet, httpProtocol, httpPort).\n");
	    fr.write("hacl(internet, "+hostname+", someProtocol, somePort).\n");
	    fr.write("attackerLocated(internet).\n");
	    fr.write("attackGoal(execCode("+hostname+", _)).\n");
            fr.close();
    		
    	}
    	
    	catch (Exception e){
    		
    		e.printStackTrace();
    		
    	}
    	
    	
    	
    }
	public static void writeTpls(ArrayList al, String hostname){
		
		String cveid="";
		String lose_types="";
		String range="";
		String software="";
		String severity="";
		String access="";
		
		try{
		Connection con = getConnection();
		Statement sql = con.createStatement();
		int l=al.size();
		FileWriter fr= new FileWriter("results.P");
		
		for(int i=0;i<l;i++){
			
		String query = "select * from nvd where id=\""+al.get(i)+"\"";
		//System.out.println(query);
		ResultSet result = sql.executeQuery(query);
		if (result.next()){
		cveid = result.getString("id");
		lose_types = result.getString("lose_types");
		range = result.getString("rng");
		software = result.getString("soft");
		severity = result.getString("severity");
		access=result.getString("access");
		String tuple="vuln_exists('"+hostname+"','"+cveid+"','"+software+"',["+range+"],["+lose_types+"],'"+severity+"','"+access+"').\n";
		//System.out.println(tuple);
		fr.write(tuple);
		}
		else continue;

		
		}
		fr.close();
		}
		catch (SQLException ex) {
			System.err.println("SQLException:" + ex.getMessage());
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}


}
