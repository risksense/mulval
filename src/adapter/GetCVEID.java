import java.io.File;
import java.io.FileWriter;
import java.util.Iterator;
import java.util.List;

import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import java.util.Hashtable;

public class GetCVEID {

	public static void main(String[] args) {
		String name = args[0];
		getCVEs(name);
	}

	public static String getHostname(String filename){
		String hname="";
		try {
			SAXReader saxReader = new SAXReader(); 
			Document document = saxReader.read(filename);
			Element hostname = (Element)document.selectSingleNode(
					"/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='oval_system_characteristics']/*[local-name(.)='system_info']/*[local-name(.)='primary_host_name']"); 
			String hname1 = hostname.getText();
			int in = hname1.indexOf('.');  //only keep the string before the first dot
			//if no dot, then ignore it
			if(in == -1)
			      hname = hname1 ;
			else //take the machine domain name
			    hname = hname1.substring(0,in);
			System.out.println("host name is: "+hname);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return hname;	
	}

	@SuppressWarnings("unchecked")
	public static void getCVEs(String filename) {
		Hashtable ovalIDs = makehashTable(filename);
		String hname = getHostname(filename);
		try{
			FileWriter fr = new FileWriter("CVE.txt");
			fr.write(hname+"\n");
			SAXReader saxReader = new SAXReader(); 
			Document document = saxReader.read(new File(filename));
			Element definitions = (Element)   document.selectSingleNode( "/*[local-name(.)='oval_results']/*[local-name(.)='oval_definitions']/*[local-name(.)='definitions']"   ); 
			List definition=document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='oval_definitions']/*[local-name(.)='definitions']/*[local-name(.)='definition']" ); 
			Iterator def = definition.iterator();
			while(def.hasNext()) {
				Element deft = (Element)def.next();
				//skip if the element is inventory
				String type = deft.attributeValue("class");
				String id = deft.attributeValue("id");
				if(type.contains( "inventory"))
					continue;
				if(ovalIDs.containsKey(id)) {
					String cve = deft.element("metadata").element("reference").attributeValue("ref_id");
					fr.write(cve+"\n");
				}
			}
			fr.close();
		}
		 catch (Exception e) {
			 e.printStackTrace();
		 }
	}

	@SuppressWarnings("unchecked")
	public static Hashtable<String, Boolean>  makehashTable(String filename){
		Hashtable<String, Boolean> hs= new Hashtable<String, Boolean>();
		try {
			SAXReader saxReader = new SAXReader(); 
			Document document = saxReader.read(new File(filename));
			List <String>ldid = document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='definitions']/*[local-name(.)='definition']/@definition_id" ); 
			Iterator itdid = ldid.iterator();
			List <String>rst = document.selectNodes("/*[local-name(.)='oval_results']/*[local-name(.)='results']/*[local-name(.)='system']/*[local-name(.)='definitions']/*[local-name(.)='definition']/@result" ); 
			Iterator result = rst.iterator();
			while(itdid.hasNext()){
				Attribute defid = (Attribute)itdid.next();
				Attribute rs = (Attribute)result.next();
				if (rs.getText().contains("true")){
					hs.put(defid.getText(), true);
				}
			}
		}
		catch (Exception e) {
			 e.printStackTrace();
		}
		return hs;
	}
}
