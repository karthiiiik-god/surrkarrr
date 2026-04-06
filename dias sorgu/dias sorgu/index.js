const { Client, GatewayIntentBits } = require('discord.js');

const client = new Client({
    intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages]
});

const TOKEN = 'YOUR_BOT_TOKEN_HERE'; // Replace with your bot token

let statusIndex = 0;
const statuses = [
    { name: 'discord.gg/dias | OsiBesT', type: 3 }, // Watching
    { name: 'Dias ❤️ OsiBest', type: 0 } // Playing, but since it's text, maybe use 0 for custom
];

client.once('ready', () => {
    console.log(`Logged in as ${client.user.tag}!`);

    // Set initial status
    client.user.setActivity(statuses[statusIndex].name, { type: statuses[statusIndex].type });

    // Change status every 1 minute (60000 ms)
    setInterval(() => {
        statusIndex = (statusIndex + 1) % statuses.length;
        client.user.setActivity(statuses[statusIndex].name, { type: statuses[statusIndex].type });
    }, 60000);
});

client.login(TOKEN);
