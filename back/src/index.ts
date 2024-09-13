import { PORT } from "./config/envs";
import app from "./server";
import "reflect-metadata"
import { AppDataSource } from "./config/dataSource";

const initialize = async () => {
    console.log("Initializing server");
    await AppDataSource.initialize();
    console.log("Database initialized");
   
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

initialize();

