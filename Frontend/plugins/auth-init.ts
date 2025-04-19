import { useAuthStore } from "~/store/authStore";
import { defineNuxtPlugin, useNuxtApp } from "#imports";

export default defineNuxtPlugin(async (nuxtApp) => {
  // Check if running on server OR initial client load after SSR
  // Use import.meta here as plugins can run in universal context
  if (import.meta.server || !nuxtApp.payload.serverRendered) {
    const authStore = useAuthStore();
    if (!authStore.isInitialized) {
      // console.log("Running auth check plugin...");
      await authStore.checkAuthStatus();
    }
  }
});
