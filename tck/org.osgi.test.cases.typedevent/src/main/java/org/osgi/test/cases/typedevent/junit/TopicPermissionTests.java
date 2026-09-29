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

package org.osgi.test.cases.typedevent.junit;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.osgi.test.assertj.permission.PermissionAssertions.assertThat;

import java.security.Permission;
import java.security.PermissionCollection;
import java.util.PropertyPermission;

import org.junit.jupiter.api.Test;
import org.osgi.service.typedevent.TopicPermission;

public class TopicPermissionTests {

	@Test
	public void testInvalid() {
		invalidTopicPermission("a/b/c", "x");
		invalidTopicPermission("a/b/c", "   subscribe  ,  x   ");
		invalidTopicPermission("a/b/c", "");
		invalidTopicPermission("a/b/c", "      ");
		invalidTopicPermission("a/b/c", null);
		invalidTopicPermission("a/b/c", ",");
		invalidTopicPermission("a/b/c", ",xxx");
		invalidTopicPermission("a/b/c", "xxx,");
		invalidTopicPermission("a/b/c", "subscribe,");
		invalidTopicPermission("a/b/c", "publish,   ");
		invalidTopicPermission("a/b/c", "subscribeme,");
		invalidTopicPermission("a/b/c", "publishme,");
		invalidTopicPermission("a/b/c", ",subscribe");
		invalidTopicPermission("a/b/c", ",publish");
		invalidTopicPermission("a/b/c", "   subscribeme   ");
		invalidTopicPermission("a/b/c", "   publishme     ");
		invalidTopicPermission("a/b/c", "   subscrib");
		invalidTopicPermission("a/b/c", "   publis");
		invalidTopicPermission("", "   publish");
	}

	@Test
	public void testActions() {
		Permission op = new PropertyPermission("java.home", "read");

		TopicPermission p11 = new TopicPermission("com/foo/service1",
				"    SUBSCRIBE,publish   ");
		TopicPermission p12 = new TopicPermission("com/foo/service1",
				"PUBLISH  ,   subscribe");
		TopicPermission p13 = new TopicPermission("com/foo/service1",
				"publISH   ");
		TopicPermission p14 = new TopicPermission("com/foo/service1",
				"    Subscribe    ");

		assertThat(p11).implies(p11, p12, p13, p14).doesNotImply(op);
		assertThat(p12).implies(p11, p12, p13, p14);
		assertThat(p13).implies(p13).doesNotImply(p11, p12, p14);
		assertThat(p14).implies(p14).doesNotImply(p11, p12, p13);

		assertThat(p11).isEquivalentTo(p11).isEquivalentTo(p12);
		assertThat(p12).isEquivalentTo(p11).isEquivalentTo(p12);
		assertThat(p13).isEquivalentTo(p13);
		assertThat(p14).isEquivalentTo(p14);

		assertNotEquivalent(p11, p13, p14);
		assertNotEquivalent(p12, p13, p14);
		assertNotEquivalent(p13, p11, p12, p14);
		assertNotEquivalent(p14, p11, p12, p13);

		PermissionCollection pc = p13.newPermissionCollection();
		assertThat(pc).hasNoElements()
				.doesNotImply(p11)
				.accepts(p14)
				.implies(p14)
				.doesNotImply(p11, p12, p13)
				.accepts(p13)
				.implies(p11, p12, p13, p14)
				.rejects(op);

		pc = p13.newPermissionCollection();
		assertThat(pc).accepts(p13)
				.implies(p13)
				.doesNotImply(p11, p12, p14)
				.accepts(p14)
				.implies(p11, p12, p13, p14);

		pc = p11.newPermissionCollection();
		assertThat(pc).accepts(p11).implies(p11, p12, p13, p14);
		pc.setReadOnly();
		assertThat(pc).rejects(p12).hasElements();

		assertThat(p11).isSerializable();
		assertThat(p12).isSerializable();
		assertThat(p13).isSerializable();
		assertThat(p14).isSerializable();
	}

	@Test
	public void testNames() {
		TopicPermission p21 = new TopicPermission("com/foo/service2",
				"subscribe");
		TopicPermission p22 = new TopicPermission("com/foo/*", "subscribe");
		TopicPermission p23 = new TopicPermission("com/*", "subscribe");
		TopicPermission p24 = new TopicPermission("*", "subscribe");

		assertThat(p21).implies(p21).doesNotImply(p22, p23, p24);
		assertThat(p22).implies(p21, p22).doesNotImply(p23, p24);
		assertThat(p23).implies(p21, p22, p23).doesNotImply(p24);
		assertThat(p24).implies(p21, p22, p23, p24);

		PermissionCollection pc = p21.newPermissionCollection();
		assertThat(pc).accepts(p21)
				.implies(p21)
				.doesNotImply(p22, p23, p24)
				.accepts(p22)
				.implies(p21, p22)
				.doesNotImply(p23, p24)
				.accepts(p23)
				.implies(p21, p22, p23)
				.doesNotImply(p24)
				.accepts(p24)
				.implies(p21, p22, p23, p24);

		assertThat(p22.newPermissionCollection()).accepts(p22)
				.implies(p21, p22)
				.doesNotImply(p23, p24);

		assertThat(p23.newPermissionCollection()).accepts(p23)
				.implies(p21, p22, p23)
				.doesNotImply(p24);

		assertThat(p24.newPermissionCollection()).accepts(p24)
				.implies(p21, p22, p23, p24);

		assertThat(p21).isSerializable();
		assertThat(p22).isSerializable();
		assertThat(p23).isSerializable();
		assertThat(p24).isSerializable();
	}

	@Test
	public void testActionImplications() {
		TopicPermission publish = new TopicPermission("*", "publish");
		TopicPermission subscribe = new TopicPermission("*", "subscribe");

		assertThat(publish).implies(publish).doesNotImply(subscribe);
		assertThat(subscribe).implies(subscribe).doesNotImply(publish);
	}

	@Test
	public void testSingleLevelWildcards() {
		TopicPermission p31 = new TopicPermission("com/foo/service3",
				"subscribe");
		TopicPermission p32 = new TopicPermission("com/+/service3",
				"subscribe");
		TopicPermission p33 = new TopicPermission("com/+/+", "subscribe");
		TopicPermission p34 = new TopicPermission("+", "subscribe");
		TopicPermission p35 = new TopicPermission("+/foo/+", "subscribe");

		// Specific topic implies itself, but no wildcard
		assertThat(p31).implies(p31).doesNotImply(p32, p33, p34);

		// Single-level wildcard implies specific matching topic; the more
		// specific single-level wildcard does not imply the less specific
		assertThat(p32).implies(p31).doesNotImply(p33, p35);

		// Multiple single-level wildcards imply matching topics
		assertThat(p33).implies(p31, p32);

		// + alone only implies single-level topics
		assertThat(p34).doesNotImply(p31, p32, p33);

		// Test with permission collection
		assertThat(p31.newPermissionCollection()).accepts(p31)
				.implies(p31)
				.doesNotImply(p32, p33)
				.accepts(p32)
				.implies(p31, p32)
				.doesNotImply(p33)
				.accepts(p33)
				.implies(p31, p32, p33);

		assertThat(p31).isSerializable();
		assertThat(p32).isSerializable();
		assertThat(p33).isSerializable();
		assertThat(p34).isSerializable();
		assertThat(p35).isSerializable();
	}

	@Test
	public void testSingleLevelWildcardWithMultiLevel() {
		TopicPermission p41 = new TopicPermission("com/foo/bar/baz",
				"subscribe");
		TopicPermission p42 = new TopicPermission("com/+/*", "subscribe");
		TopicPermission p43 = new TopicPermission("com/foo/*", "subscribe");
		TopicPermission p44 = new TopicPermission("+/*", "subscribe");
		TopicPermission p45 = new TopicPermission("com/+/+", "subscribe");
		TopicPermission p46 = new TopicPermission("com/foo", "subscribe");

		// Single-level wildcard + multi-level wildcard implies matching
		// topics; com/+/* implies com/foo/* and com/+/+, but not com/foo
		assertThat(p42).implies(p41, p43, p45).doesNotImply(p46);
		assertThat(p44).implies(p41);

		// Multi-level wildcard alone implies matching topics; the more
		// specific does not imply the less specific
		assertThat(p43).implies(p41).doesNotImply(p42, p44);
		assertThat(p41).doesNotImply(p42, p43, p44);

		// com/+/+ implies neither com/+/* nor com/foo
		assertThat(p45).doesNotImply(p42, p46);

		assertThat(p41).isSerializable();
		assertThat(p42).isSerializable();
		assertThat(p43).isSerializable();
		assertThat(p44).isSerializable();
		assertThat(p45).isSerializable();
		assertThat(p46).isSerializable();
	}

	private static void invalidTopicPermission(String name, String actions) {
		assertThatIllegalArgumentException()
				.as("TopicPermission(%s, %s) created with invalid actions", name, actions)
				.isThrownBy(() -> new TopicPermission(name, actions));
	}

	/**
	 * Not equal in either direction and, as the TCK always required, with a
	 * different hash code.
	 */
	private static void assertNotEquivalent(Permission permission, Permission... others) {
		for (Permission other : others) {
			assertThat(permission).isNotEquivalentTo(other).doesNotHaveSameHashCodeAs(other);
		}
	}
}
