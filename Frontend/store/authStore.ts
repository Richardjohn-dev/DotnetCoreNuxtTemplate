import { defineStore } from "pinia";
import type { UserInfoResponse, ProblemDetails, ApiResponse } from "~/types";
import { useApiFetch, useApi, ApiError } from "~/composables/useApiFetch";
import { navigateTo } from "#imports";
import { useErrorStore } from "./errorStore";

interface AuthState {
  isLoggedIn: boolean;
  user: UserInfoResponse | null;
  status: "idle" | "loading" | "error" | "success" | "checking";
  isInitialized: boolean;
}

export const useAuthStore = defineStore("auth", {
  state: (): AuthState => ({
    isLoggedIn: false,
    user: null,
    status: "idle",
    isInitialized: false,
  }),
  getters: {
    isAuthenticated: (state): boolean => state.isLoggedIn,
    currentUser: (state): UserInfoResponse | null => state.user,
    isAdmin: (state): boolean => state.user?.roles?.includes("Admin") ?? false,
    isLoading: (state): boolean => state.status === "loading",
    isCheckingAuth: (state): boolean => state.status === "checking",
  },
  actions: {
    _setAuthInfo(user: UserInfoResponse | null) {
      this.user = user;
      this.isLoggedIn = !!user;
      this.status = user ? "success" : "idle";
      const errorStore = useErrorStore();
      errorStore.clearErrors();
    },
    _setError(error: unknown) {
      const errorStore = useErrorStore();
      errorStore.setError(error);
      this.status = "error";
      this.isLoggedIn = false;
      this.user = null;
    },
    _setLoading() {
      this.status = "loading";
      const errorStore = useErrorStore();
      errorStore.clearErrors();
    },

    _setChecking() {
      this.status = "checking";
      const errorStore = useErrorStore();
      errorStore.clearErrors();
    },

    _setIdle() {
      this.status = "idle";
      const errorStore = useErrorStore();
      errorStore.clearErrors();
      this.isInitialized = true;
    },
    async login(credentials: { email: string; password: string }) {
      this._setLoading();
      const api = useApi();
      try {
        const response = await api.post<UserInfoResponse>(
          "/auth/login",
          credentials
        );
        this._setAuthInfo(response.payload);
        this.isInitialized = true;
        return true;
      } catch (error: unknown) {
        this._setError(error);
        return false;
      }
    },
    async register(details: {
      email: string;
      password: string;
      confirmPassword: string;
    }) {
      this._setLoading();
      const api = useApi();
      try {
        await api.post<UserInfoResponse>("/auth/register", details);
        this.status = "success";
        return true;
      } catch (error: unknown) {
        this._setError(error);
        return false;
      }
    },

    async fetchUser() {
      if (this.isLoggedIn) {
        this.isInitialized = true;
        return;
      }
      this._setChecking();
      const api = useApi();
      try {
        const response = await api.get<UserInfoResponse>("/users/me");
        this._setAuthInfo(response.payload);
      } catch (error: unknown) {
        if (
          (error instanceof ApiError && error.statusCode === 401) ||
          (error instanceof Error && error.message === "UnauthorizedRedirect")
        ) {
          this._setAuthInfo(null); // Just log out silently
        } else {
          this._setError(error);
        }
      } finally {
        this.isInitialized = true;
        if (this.status === "checking") this._setIdle();
      }
    },

    async checkAuthStatus() {
      if (!this.isInitialized) {
        await this.fetchUser();
      }
    },
    async logout() {
      this._setLoading();
      const api = useApi();
      const wasLoggedIn = this.isLoggedIn;
      try {
        await api.post<boolean>("/auth/logout");
      } catch (error: unknown) {
        console.error(
          "Logout API call failed:",
          error instanceof Error ? error.message : error
        );
      } finally {
        this._setAuthInfo(null);
        this.isInitialized = true;
        if (import.meta.client && wasLoggedIn) {
          await navigateTo("/login", { replace: true });
        } else if (import.meta.client) {
          console.log("Logout called but user was not logged in.");
        }
      }
    },
  },
});
