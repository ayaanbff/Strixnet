const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');


const app = express();
const server = http.createServer(app);


const io = new Server(server, {
    cors: { origin: "*" }
});


app.use(cors());
app.use(express.json()); 
app.use(express.static(__dirname)); 
app.get('/', (req, res) => {
res.sendFile(__dirname + '/b1.html')

})
app.get('/sw', (req, res) => {
res.sendFile(__dirname + '/b1.html')

})



app.post('/api/stats', (req, res) => {
    io.emit('stats_update', req.body);
    res.status(200).json({ status: "success" });
});
app.post('/api/ingest-alert', (req, res) => {
    const alertData = req.body;
    
    
    console.log(`[ALERT RECEIVED] -> ${alertData.threat_class} | ${alertData.flow_identifier}`);

    
    io.emit('new_threat_alert', alertData);

    
    

    
    res.status(200).json({ status: "success", message: "Alert broadcasted to UI" });
});




io.on('connection', (socket) => {
    console.log(`[+] SOC Dashboard Connected: ${socket.id}`);
    
    socket.on('disconnect', () => {
        console.log(`[-] SOC Dashboard Disconnected: ${socket.id}`);
    });
});


const PORT = 3000;
server.listen(PORT, () => {
    console.log(`[*] NTRO Controller Server running on http://localhost:${PORT}`);
});

