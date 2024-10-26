export {};

declare global {
  interface Window {
    // Add your Go function bindings here
    sayHello: (name: string) => Promise<string>;
    getData: () => Promise<{ id: number; name: string }>;
    // Add more function types as needed
  }
}