
var jdevs;
var curtime_;


function unixtime()
{
   return Math.floor(Date.now() / 1000);
}


function generateTableHead(table)
{
   var data = ["address", "age", "network address", "description"];
   let thead = table.createTHead();
   let row = thead.insertRow();
   for (let key of data)
   {
      let th = document.createElement("th");
      let text = document.createTextNode(key);
      th.appendChild(text);
      row.appendChild(th);
   }
}


function age_string(t)
{
   var d = curtime_ - t;

   if (d < 60)
   {
      return d + " s";
   }
   if (d < 3600)
   {
      return Math.floor(d / 60) + " min";
   }

   return Math.floor(d / 3600) + " h";
}


function generateTable(table, data)
{
   for (let element of data)
   {
      let row = table.insertRow();
      var cell, text, dev;

      // MAC address
      cell = row.insertCell();
      cell.style.fontFamily = "monospace";

      dev = jdevs.find(({addr}) => addr.toLowerCase() == element["addr"]);
      cell.style.backgroundColor = dev ? "PaleGreen" : "Salmon";

      text = document.createTextNode(element["addr"]);
      cell.appendChild(text);

      // time
      cell = row.insertCell();
      //cell.style.fontFamily = "monospace";
      text = document.createTextNode(age_string(element["time"]));
      cell.appendChild(text);

      // network addresses
      cell = row.insertCell();
      var nw = "";
      if (element.addresses !== undefined)
      {
         element.addresses.sort((a, b) => b.time - a.time);
         element.addresses.forEach(function(key)
         {
            //if (key["type"] == 2)
            {
               if (nw.length > 0)
                  nw += ",<br>";
               nw += key["addr"] + " (" + age_string(key["time"]) + ")";
            }
         });
      }
      //text = document.createTextNode(nw);
      //cell.appendChild(text);
      cell.innerHTML = nw;

      // known device
      //if (dev !== undefined)
      if (dev === undefined)
         dev = {"name": "__UNKNOWN__"};

      cell = row.insertCell();
      //cell.style.fontFamily = "monospace";
      text = document.createTextNode(dev.name);
      cell.appendChild(text);

   }
}


async function fetchData()
{
   try
   {
      //const response = await fetch('dump.json?v=' + unixtime());
      const response = await fetch('/dump/?dump');
      const jdata = await response.json();
      //console.log(jdata);

      const devs = await fetch("known_devs.json?v=" + unixtime());
      jdevs = await devs.json();
      //console.log(jdevs);

      let table = document.querySelector("table");
      let data = Object.keys(jdata.addresses[1]);
      //generateTableHead(table, data);
      generateTableHead(table);
      jdata.addresses.sort((a, b) => b.time - a.time);
      curtime_ = jdata.curtime;
      generateTable(table, jdata.addresses);

   }
   catch (error)
   {
      console.error('Error fetching data:', error);
   }
}


fetchData();

