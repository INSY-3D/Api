import express from 'express';
declare class NexusPayServer {
    private app;
    private port;
    constructor();
    private setupMiddleware;
    private setupRoutes;
    private setupErrorHandling;
    start(): Promise<void>;
    getApp(): express.Application;
}
declare const server: NexusPayServer;
export default server;
//# sourceMappingURL=server.d.ts.map