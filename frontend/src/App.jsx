import { useEffect, useState } from "react";
import axios from "axios";

export default function App(){

const [alerts,setAlerts]=useState([]);

useEffect(()=>{

axios.get("http://127.0.0.1:8000/alerts")
.then(response=>{
setAlerts(response.data);
})
.catch(error=>{
console.log(error);
});

},[]);

const card={
background:"#1e293b",
padding:"25px",
borderRadius:"20px"
}
return(

<div style={{
background:"#020617",
minHeight:"100vh",
padding:"40px",
color:"white"
}}>

<h1 style={{fontSize:"42px"}}>
Microsoft Security Copilot
</h1>

<p>
Autonomous AI Security Agents
</p>


<div style={{
display:"grid",
gridTemplateColumns:"repeat(4,1fr)",
gap:"20px",
marginTop:"40px"
}}>

<div style={card}>
<h2>Threats Detected</h2>
<h1>37</h1>
</div>

<div style={card}>
<h2>Critical Incidents</h2>
<h1>6</h1>
</div>

<div style={card}>
<h2>Vulnerabilities</h2>
<h1>14</h1>
</div>

<div style={card}>
<h2>Breaches Contained</h2>
<h1>4</h1>
</div>

</div>


<h2 style={{marginTop:"50px"}}>
Live Threat Feed
</h2>


{alerts.map((a,i)=>(
<div
key={i}
style={{
background:"#1e293b",
padding:"20px",
marginTop:"20px",
borderRadius:"16px"
}}
>
<h3>{a.threat}</h3>
<p>{a.priority}</p>

</div>
))}

</div>

)}