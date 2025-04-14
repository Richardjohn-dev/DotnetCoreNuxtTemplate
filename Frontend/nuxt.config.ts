// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: true },

  modules: [
    "@pinia/nuxt",
    // '@nuxtjs/tailwindcss', // Uncomment if needed
  ],

  // Runtime Config
  runtimeConfig: {
    apiSecret: "",

    public: {
      apiBaseUrl: "https://localhost:7001/api", // Default value
    },
  },

  compatibilityDate: "2025-04-13",
});