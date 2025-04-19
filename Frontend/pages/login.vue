<script setup lang="ts">
import { ref, onMounted, computed } from "vue";
import { useAuthStore } from "~/store/authStore";
import { useErrorStore } from "~/store/errorStore";
import { navigateTo, useRoute, useRuntimeConfig } from "#app";

const authStore = useAuthStore();
const errorStore = useErrorStore();
const route = useRoute();
const config = useRuntimeConfig();
const email = ref("");
const password = ref("");

// Use computed properties for easier access to error state
const validationErrors = computed(() => errorStore.validationErrors);
const generalError = computed(
  () => errorStore.errorDetail || errorStore.errorTitle
);
const isLoading = computed(() => authStore.isLoading);

const formError = ref<string | null>(null); // For local form errors like password mismatch

// --- Password Login Handler ---
const handleLogin = async () => {
  formError.value = null; // Clear local form error
  const success = await authStore.login({
    email: email.value,
    password: password.value,
  });
  if (success) {
    const redirectPath = (route.query.redirect as string) || "/";
    await navigateTo(redirectPath, { external: false, replace: true });
  }
  // Errors are now reactive via computed properties from the error store
};

// --- Google Login Handler ---
const handleGoogleLogin = () => {
  formError.value = null; // Clear local errors before redirect
  const backendChallengeUrl = `${config.public.apiBaseUrl}/auth/external-login?provider=Google`;
  // Optional: Add returnUrl for specific redirect after Google login
  // const returnUrl = '/dashboard'; // Example
  // const challengeUrlWithReturn = `${backendChallengeUrl}&returnUrl=${encodeURIComponent(returnUrl)}`;
  window.location.href = backendChallengeUrl;
};

// --- Display errors passed back from external callback ---
onMounted(() => {
  const queryError = route.query.error as string;
  if (queryError && !generalError.value) {
    // Update error store with external login error
    errorStore.setError({
      title: "External Login Failed",
      detail: queryError,
    });
  }
});
</script>

<template>
  <div>
    <h1>Login</h1>
    <form @submit.prevent="handleLogin" aria-label="Login Form">
      <div class="form-group">
        <label for="email">Email:</label>
        <input
          type="email"
          id="email"
          v-model="email"
          required
          autocomplete="email"
          :aria-invalid="!!validationErrors?.Email || !!validationErrors?.email"
          aria-describedby="email-error"
        />
        <span
          id="email-error"
          v-if="validationErrors?.Email || validationErrors?.email"
          class="error-text"
        >
          {{ (validationErrors?.Email || validationErrors?.email)?.join(", ") }}
        </span>
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input
          type="password"
          id="password"
          v-model="password"
          required
          autocomplete="current-password"
          :aria-invalid="
            !!validationErrors?.Password || !!validationErrors?.password
          "
          aria-describedby="password-error"
        />
        <span
          id="password-error"
          v-if="validationErrors?.Password || validationErrors?.password"
          class="error-text"
        >
          {{
            (validationErrors?.Password || validationErrors?.password)?.join(
              ", "
            )
          }}
        </span>
      </div>
      <button type="submit" :disabled="isLoading">
        <span v-if="isLoading">Logging in...</span>
        <span v-else>Login</span>
      </button>
    </form>

    <hr />

    <button @click="handleGoogleLogin" :disabled="isLoading">
      <span v-if="isLoading">Loading...</span>
      <span v-else>Sign in with Google</span>
    </button>

    <div v-if="generalError || formError" class="error-message" role="alert">
      {{ generalError || formError }}
    </div>

    <p>
      Don't have an account? <NuxtLink to="/register">Register here</NuxtLink>
    </p>
  </div>
</template>

<style scoped>
.form-group {
  margin-bottom: 1rem;
}
label {
  display: block;
  margin-bottom: 0.25rem;
}
input {
  width: 100%;
  padding: 0.5rem; /* Add more styling */
}
.error-text {
  color: red;
  font-size: 0.8em;
  display: block;
}
.error-message {
  color: red;
  margin-top: 1rem;
  padding: 0.5rem;
  border: 1px solid red;
}
hr {
  margin: 1.5rem 0;
}
button {
  /* Add styling */
  padding: 0.5rem 1rem;
  cursor: pointer;
}
button:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}
</style>
