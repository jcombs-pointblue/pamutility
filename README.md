# pamutility
Privileged Access Manager Utility

This utility will create a vault and credential for Linux hosts in Microfocus PAM.  This an Ant based NetBeans project.

The command to load a single host is:

        java -jar pamUtility.jar '10.155.63.251' 'admin' 'adminpw' 'fullHostDnsName' 22 root 'rootpw'


10.155.63.251 is a PAM server running the Framework Manager

22 is the ssh port of the host. Change this if needed

'root' is the account we are creating the credential for.


To load multiple servers from a CSV file use the following command:

         java -jar pamUtility.jar '10.155.63.251' 'admin' 'adminpw' yourcsv.csv


here is an example of what should be in the CSV

someserver.myorg.com,22,root,rootpw

anotherserver.myorg.com,22,root,rootpw


NOTE!!! The framework server must be able to SSH to the host since it retrieves the host key automatically.
NOTE: you will need to run the package-for-store Ant task manually to generate a single jar file with all dependedencies included.

