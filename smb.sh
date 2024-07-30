#!/usr/bin/env bash


if [ $# -eq 0 ]; then
	echo "No arguments provided. Kinldy enter the argument in this 'domain\username:password' format"
	exit 1
fi
	
nmap -sn -T5 --open --min-parallelism 100 -oG internalip1.txt 10.0.0.0/10



cat internalip1.txt | grep -i 'up' | cut -d ' ' -f 2 | grep -v 'Nmap' > test.txt  mv test.txt internalip1.txt



nmap -sn -T5 --open --min-parallelism 100 -oG internalip2.txt 10.64.0.0/10


cat internalip2.txt | grep -i 'up' | cut -d ' ' -f 2 | grep -v 'Nmap' > test.txt  mv test.txt internalip2.txt



nmap -sn -T5 --open --min-parallelism 100 -oG internalip3.txt 10.128.0.0/10



cat internalip3.txt | grep -i 'up' | cut -d ' ' -f 2 | grep -v 'Nmap' > test.txt  mv test.txt internalip3.txt



nmap -sn -T5 --open --min-parallelism 100 -oG internalip4.txt 10.192.0.0/10 



cat internalip4.txt | grep -i 'up' | cut -d ' ' -f 2 | grep -vi 'Nmap' > test.txt  mv test.txt internalip4.txt




nmap -p 445 -oG 445_scan1.gnmap -iL internalip1.txt --open



nmap -p 445 -oG 445_scan2.gnmap -iL internalip2.txt --open



nmap -p 445 -oG 445_scan3.gnmap -iL internalip3.txt --open



nmap -p 445 -oG 445_scan4.gnmap -iL internalip4.txt --open



./SMBHunt.pl -a -f $1 -i 445_scan1.gnmap -o shares_found1.txt



./SMBHunt.pl -a -f $1 -i 445_scan2.gnmap -o shares_found2.txt



./SMBHunt.pl -a -f $1 -i 445_scan3.gnmap -o shares_found3.txt



./SMBHunt.pl -a -f $1 -i 445_scan4.gnmap -o shares_found4.txt

#you can add manual filteration process here using grep -v option 

cat shares_found1.txt  | tee -a shares_filtered1.txt


cat shares_found2.txt | tee -a shares_filtered2.txt


cat shares_found3.txt | tee -a shares_filtered3.txt


cat shares_found4.txt | tee -a shares_filtered4.txt



./SMBList.pl -c $1 -s shares_filtered1.txt -o ouput_dir1 
	


./SMBList.pl -c $1 -s shares_filtered2.txt -o ouput_dir2 



./SMBList.pl -c $1 -s shares_filtered3.txt -o ouput_dir3 



./SMBList.pl -c $1 -s shares_filtered4.txt -o ouput_dir4 


#Dont add th -m flag in the SMBList its giving less results not reliable.

export hiren=$hiren$(pwd)


mkdir all_sensitive_file


cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Eiv 'Payroll_Accrual_Entries|FAQs\.pdf|Discrepancy\.pdf|\.doc|\.lnk|\.xls\.url|\.htm|\.url|\.txt|\.pyi|\.idx|\.dat|\.btr|\.vml|\.otf|\.indd|\.ai|\.TTF|HR_Payroll&Expense_Author' | grep -i 'payroll.*$' | tee -a $hiren/all_sensitive_file/payroll.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Eiv '\.zip|\.pyi|\.idx|\.dat|\.btr|\.vml'| grep -i payslip | tee -a $hiren/all_sensitive_file/payslip.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -i 'stub' | grep -i 'pay' | tee -a $hiren/all_sensitive_file/paystubs.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Eiv '\.docs|\.msg|\.jpg|\.msg|\.pyi|\.idx|\.dat|\.btr|\.vml|\.html'| grep -i 'Form16' | tee -a $hiren/all_sensitive_file/form16.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 |grep -Evi 'Non_Confidential|Non-Confidential|namespace-confidential|\.xml|\.htm|\.jpg|confidential_computing|\.gif|\.c$|\.sc$|\.yaml|\.png|\.so$|\.h$|\.thmx|\.fm$|technotes_confidential|SQL_Server_Workloads-confidential|\.java|\.go$|\.pyi|\.debug|confidentialledger'| grep -i 'Confidential' | tee -a $hiren/all_sensitive_file/Confidential.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Eiv '\.docs|\.jpg|\.DIS|\.rpt|PSO_STLT_for_Deferred_Revenue|M_A_Net_down_VMC_AWS_Revenue_Automation|AW_US_Def_d_Revenue_Earn_out|RevOps.Quarterly.Related.Party.Revenue|RPA_PROD|RPA_STAGE|Cat_Prod_ModelN|Automation|PerformanceTesting|\.c$|\.mdb$|jenkins|\.sql|\.php|\.rpt|\.xlsb|\.yaml|\.dis|\.tds|\.tdsx|\.twb|\.htm|\.gif|\.swf|omercier|\.stop|\.q$|\.atr|OracleBI|\.js|\.bin|Oraclecontractors|\.pyi'| grep -i 'Revenue' | grep -Ei '\.txt|\.docx|\.doc|\.xlsx|\.xlsm|\.xls|\.csv|\.msg|\.pdf' | tee -a $hiren/all_sensitive_file/Revenue.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Evi '\.htm|\.exe|\.url|\.msi|\.png|\.gif|\.svg|\.tiff|\.tif|\.less|\.css|\.xml|\.met|software|cshare|aarce|joe|data-jobs|\.c$|Links|vcperf|sc-dbc|\.fm$|\.pyi|\.js|\.sql' | grep -i 'important' | tee -a $hiren/all_sensitive_file/importantfiles.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.pdf|\.xls|\.doc|\.xlsx|\.xlsm' |grep -i 'finance' | tee -a $hiren/all_sensitive_file/finance.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Evi 'RPA_PROD'| grep -iw 'Aadhar|\.pyi' | tee -a $hiren/all_sensitive_file/aadhar.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -i 'pancard' | tee -a $hiren/all_sensitive_file/pancard.txt 



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 |grep -Ei '\.pdf|\.docx|\.doc|\.jpg|\.jpeg'| grep -i 'passport' | tee -a $hiren/all_sensitive_file/passport.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 |grep -Ei '\.pdf|\.docx|\.doc|\.jpg|\.jpeg'| grep -wi 'uan' | tee -a $hiren/all_sensitive_file/uan.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 |grep -Ei '\.pdf|\.docx|\.doc|\.jpg|\.jpeg'| grep -Evi 'fax|Sales' | grep -wi 'ssn' | tee -a $hiren/all_sensitive_file/ssn.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Eiv 'personality|personaluser|personalized|personalfiles|personalsettings|personallicense|angular|\.htm|\.crt|\.jar|\.etlgz|\.ini|\.odlgz|\idl|\.loggz|\.svg|\.sha|\.signature|\.cer|\.pdb|\.pqa|\.prc|\.dll|\.url|\.cfg|\.exe|\.atr|\.idx|\.dat|\.usp|\.c|\.h|\.inf|\.js|\.html|\.properties|\.keystore|\.xml|\.png|rpa_prod|personalization|personalize|\.gz|\.gif|\.ITR-1_2017|\.pyi|Personale|\.conf$|\.atr|catalogsystemprivs|privs' | grep -i 'personal' | tee -a $hiren/all_sensitive_file/PersonalInformation.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '.\xlsx|\.html|\.pdf|\.pptx|\.doc|\.docx'| grep -Eiv '\.html' | grep -i 'Agreement' | tee -a $hiren/all_sensitive_file/Agreement.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '.\xlsx|\.html|\.pdf|\.pptx|\.doc|\.docx'|grep -i 'Invoice' | tee -a $hiren/all_sensitive_file/Invoice.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.docx|\.dox|\.xlsx|\.xls|\.html|\.msg'|grep -i 'Budget' | tee -a $hiren/all_sensitive_file/budget.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.txt|\.password|\.jpeg|\.xlsx' | grep -vi 'KerberosCredentialsTest' |grep -i 'credential' | tee -a $hiren/all_sensitive_file/credential.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.txt|\.password|\.jpeg|\.xlsx|\.xls'| grep -Evi '\.template|\.aspx|goat-automation-password|goat-password|fixPasswordCancelUpgrade|\.html|TPT-Root-Password-change|CNX|\.log|\.gz|\.pyi|\.properties$|passwordsyncobjectmodel|ForgotYourPassword|Reset\ Password|PasswordPropertyTest|password_reset|HowToChangeTheAdminPassword|ResetPassword|InstallPassword|PasswordRestrictions|get_admin|ChangePassword|\.aml$'|grep -i 'Password' | tee -a $hiren/all_sensitive_file/password.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Evi '\.mxml|\.swf|\.js|\.ascx|\.strings|\.php|\.rpm|\.nib|\.pyi|\.as|.\java|\.tif|\.ai|\.ts|\.gif|\.psd|\.eps|\.java' | grep -i creditcard | tee -a $hiren/all_sensitive_file/creditcard.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.pem$|\.key$|keystore|\.pfx$|\.p12$' | grep -Eiv '\.java|\.cpp|\.html|\.keystream|\.insecure|\.dll|\.len|\.at$|\.js$|\.html|\.jks|\.readme' | tee -a $hiren/all_sensitive_file/privatekeys.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.*_rsa$|\.*_dsa$|\.*_ed25519$' | tee -a $hiren/all_sensitive_file/ssh_privatekeys.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.bash_history$|\.zsh_history|\.sh_history' | tee -a $hiren/all_sensitive_file/bashhistories.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei 'database\.yml$' | tee -a $hiren/all_sensitive_file/databasecred.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei 'jenkins\.plugins\.publish_over_ssh\.BapSshPublisherPlugin\.xml$' | tee -a $hiren/all_sensitive_file/Jenkinsssh.txt
 


cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei 'filezilla\.xml$' | tee -a $hiren/all_sensitive_file/ftppassword.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei 'terraform.tfvars$' | tee -a $hiren/all_sensitive_file/teraform.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.git-credentials$'  | tee -a $hiren/all_sensitive_file/git-credentials.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei '\.mdf$|\.sqlite$|\.sdf$' | tee -a $hiren/all_sensitive_file/databasessbackup.txt



cat $hiren/ouput_dir1/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir2/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir3/ALL_COMBINED_RESULTS.txt $hiren/ouput_dir4/ALL_COMBINED_RESULTS.txt | cut -d '|' -f 3-15 | grep -Ei 'htpasswd' | tee -a $hiren/all_sensitive_file/htapassword.txt


echo 'All Commands excecuted successfully'


