export type PollingState = {
    isRunning:boolean;
    intervalMs:number;
    timer:NodeJS.Timeout | null
}