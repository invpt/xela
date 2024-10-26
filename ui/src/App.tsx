import { createSignal } from "solid-js";

function App() {
  const [count, setCount] = createSignal(0);

  return (
    <div class="flex justify-center items-center flex-col text-white min-h-screen">
      <div class="h-[52px] flex items-end">
        <button
          class="p-2 bg-blue-500 rounded-md transition-all duration-100 ease-in-out border-b-0 border-blue-700 hover:border-b-4 active:border-b-0"
          onClick={() => setCount((count) => count + 1)}>
          count is {count()}
        </button>
      </div>
    </div>
  );
}

export default App;
