import app from "./app";
import config from "./config";
import { prisma } from "./lib/prisma";

const PORT = config.port;

const main = async () => {
    try {
        await prisma.$connect();
        console.log("Connected to Database successfully!");
        app.listen(PORT, () => {
            console.log(`Server is running at port ${PORT}`);
        })
    } catch (error) {
        console.error(error)
        await prisma.$disconnect();
        process.exit(1);
    }
}

main();