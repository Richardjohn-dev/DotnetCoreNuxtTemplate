<script setup lang="ts">
import { computed } from "vue";
import { useAuthStore } from "~/store/authStore";
import { definePageMeta } from "#imports"; // Ensure Nuxt auto-imports or import explicitly

// --- !!! IMPORTANT !!! ---
// This tells the auth.global.ts middleware that this page requires login.
definePageMeta({
  requiresAuth: true,
  // Optionally add role restrictions:
  // roles: ['Admin']
});

const authStore = useAuthStore();

// Use computed properties for cleaner template access
const currentUserEmail = computed(() => authStore.currentUser?.email);
const currentUserRoles = computed(
  () => authStore.currentUser?.roles?.join(", ") || "No roles found"
);
const isLoading = computed(
  () => authStore.isCheckingAuth || authStore.isLoading
);
</script>

<template>
  <div>
    <h1>Protected Page Example</h1>

    <div v-if="isLoading">
      <p>Loading user data...</p>
    </div>

    <div v-else-if="authStore.isAuthenticated && authStore.currentUser">
      <p>
        Welcome, <strong>{{ currentUserEmail }}</strong
        >!
      </p>
      <p>Your user ID is: {{ authStore.currentUser.userId }}</p>
      <p>Your Roles: {{ currentUserRoles }}</p>
      <p>This content is only visible to logged-in users.</p>
    </div>

    <div v-else>
      <p>
        You should not be able to see this message if the middleware is working
        correctly, as you would be redirected to login.
      </p>
    </div>

    <hr style="margin: 1rem 0" />
    <NuxtLink to="/">Go Back Home</NuxtLink>
  </div>
</template>

<style scoped>
strong {
  font-weight: bold;
}
</style>
