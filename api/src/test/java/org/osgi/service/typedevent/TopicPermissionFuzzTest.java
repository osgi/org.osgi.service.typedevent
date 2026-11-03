/*******************************************************************************
 * Copyright (c) Contributors to the Eclipse Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *******************************************************************************/

package org.osgi.service.typedevent;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PermissionCollection;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

/**
 * Fuzz tests for {@link TopicPermission} and its permission collection.
 * <p>
 * A plain {@code mvn verify} runs each test once per stored input (regression
 * mode). {@code JAZZER_FUZZ=1} fuzzes one test per run, for
 * {@code maxDuration}.
 */
class TopicPermissionFuzzTest {

	private static final String[]	ACTIONS		= {
			TopicPermission.PUBLISH, TopicPermission.SUBSCRIBE,
			TopicPermission.PUBLISH + "," + TopicPermission.SUBSCRIBE
	};

	/** Topic levels: literals and the single-level wildcard. */
	private static final String[]	LEVELS		= {
			"a", "b", "c", "+"
	};

	/**
	 * A well-formed topic name: {@code *}, or one to four levels, each a
	 * literal or {@code +}, optionally followed by {@code /*}.
	 */
	private static String topic(FuzzedDataProvider data) {
		if (data.consumeInt(0, 7) == 0) {
			return "*";
		}
		StringBuilder name = new StringBuilder();
		int levels = data.consumeInt(1, 4);
		for (int i = 0; i < levels; i++) {
			if (i > 0) {
				name.append('/');
			}
			name.append(data.pickValue(LEVELS));
		}
		if (data.consumeBoolean()) {
			name.append("/*");
		}
		return name.toString();
	}

	/**
	 * Any input: the constructor rejects only with
	 * {@link IllegalArgumentException}, and a created permission survives its
	 * canonical actions and serialization unchanged.
	 */
	@FuzzTest(maxDuration = "30s")
	void construct(FuzzedDataProvider data) throws Exception {
		String name = data.consumeString(64);
		String actions = data.consumeRemainingAsString();
		TopicPermission permission;
		try {
			permission = new TopicPermission(name, actions);
		} catch (IllegalArgumentException invalid) {
			return;
		}
		assertThat(new TopicPermission(permission.getName(),
				permission.getActions())).isEqualTo(permission)
						.hasSameHashCodeAs(permission);
		TopicPermission copy = deserialize(serialize(permission));
		assertThat(copy).isEqualTo(permission);
		assertThat(copy.implies(permission))
				.isEqualTo(permission.implies(permission));
	}

	/**
	 * A well-formed permission implies itself, and a collection holding only
	 * that permission implies exactly what the permission implies.
	 */
	@FuzzTest(maxDuration = "30s")
	void collectionWithOnePermission(FuzzedDataProvider data) {
		TopicPermission granted = new TopicPermission(topic(data),
				data.pickValue(ACTIONS));
		TopicPermission requested = new TopicPermission(topic(data),
				data.pickValue(ACTIONS));
		PermissionCollection collection = granted.newPermissionCollection();
		collection.add(granted);

		assertThat(granted.implies(granted)).as("%s implies itself", granted)
				.isTrue();
		assertThat(collection.implies(requested))
				.as("collection [%s] implies %s", granted, requested)
				.isEqualTo(granted.implies(requested));
	}

	/**
	 * A collection implies a request exactly when the permissions that imply
	 * the request's topic together grant all requested actions.
	 */
	@FuzzTest(maxDuration = "30s")
	void collectionCombinesActions(FuzzedDataProvider data) {
		TopicPermission requested = new TopicPermission(topic(data),
				data.pickValue(ACTIONS));
		TopicPermission requestedPublish = new TopicPermission(
				requested.getName(), TopicPermission.PUBLISH);
		TopicPermission requestedSubscribe = new TopicPermission(
				requested.getName(), TopicPermission.SUBSCRIBE);

		PermissionCollection collection = requested.newPermissionCollection();
		StringBuilder grants = new StringBuilder();
		boolean publish = false;
		boolean subscribe = false;
		int count = data.consumeInt(1, 4);
		for (int i = 0; i < count; i++) {
			TopicPermission granted = new TopicPermission(topic(data),
					data.pickValue(ACTIONS));
			collection.add(granted);
			grants.append(granted).append(' ');
			publish |= granted.implies(requestedPublish);
			subscribe |= granted.implies(requestedSubscribe);
		}
		String actions = requested.getActions();
		boolean expected = (!actions.contains(TopicPermission.PUBLISH)
				|| publish)
				&& (!actions.contains(TopicPermission.SUBSCRIBE) || subscribe);

		assertThat(collection.implies(requested))
				.as("collection [%s] implies %s", grants, requested)
				.isEqualTo(expected);
	}

	private static byte[] serialize(Object object) throws IOException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
			out.writeObject(object);
		}
		return bytes.toByteArray();
	}

	private static TopicPermission deserialize(byte[] bytes)
			throws IOException, ClassNotFoundException {
		try (ObjectInputStream in = new ObjectInputStream(
				new ByteArrayInputStream(bytes))) {
			return (TopicPermission) in.readObject();
		}
	}
}
