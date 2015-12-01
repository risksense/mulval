/*
Check if the database server could be connected with current credential (stored in config.txt).
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
import java.sql.SQLException;


public class mysqlConnectionChecker {

	
	public static void main(String[] args) {

		try {
			getConnection();
			
			//if the connection couldn't be established, then
			//writeConnectionSucc will not be called.
			writeConnectionSucc();
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			//System.out.println("sql exception invoked");
		    System.err.println("NVD DB connection cannot be established");
					
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
		    System.err.println("class Not found error");
					
		} catch (IOException e) {
			// TODO Auto-generated catch block
		    System.err.println("IO error");
					
		}
	}

	private static void writeConnectionSucc() {

		try {
			FileWriter fr = new FileWriter("connectionSucc.txt");

			fr.close();
		
		} catch (IOException e) {

			System.err.println("IO error");

		}
		
		
		
	}

	public static Connection getConnection() throws SQLException,

	java.lang.ClassNotFoundException, IOException {

//String url = "jdbc:mysql://localhost:3306/mulvalDB";

Class.forName("com.mysql.jdbc.Driver");

//String userName = "root";

//String password = "";

String url="";

String userName="";

String password="";

File f= new File("config.txt");

String path = f.getPath();

	BufferedReader breader= new BufferedReader(new FileReader(path));

	url=breader.readLine();

	userName=breader.readLine();

//	System.out.println(userName);
	password=breader.readLine();

	Connection con = DriverManager.getConnection(url, userName, password);

	return con;	

}
}
