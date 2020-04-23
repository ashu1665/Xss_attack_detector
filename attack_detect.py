import pyshark

print("Ip of vulnerable server\t\tPort of vulnerable server\tPayload of the attack")
print()
for pkg in pyshark.LiveCapture(interface='any', display_filter='http'):
 data=str(pkg.http)
 if "script" in data or "alert" in data:
  print(pkg.ip.dst+"\t\t\t"+pkg[pkg.transport_layer].dstport+"\t\t\t"+data.splitlines()[1])
  break   
 else:
  continue
